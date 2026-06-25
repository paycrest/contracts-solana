import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SolanaGateway } from "../target/types/solana_gateway";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { assert } from "chai";
import { AGGREGATOR_KP, TREASURY_KP } from "./helpers/setup";

describe("createOrder", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaGateway as Program<SolanaGateway>;
  const connection = provider.connection;

  // Keypairs
  const owner = provider.wallet as anchor.Wallet;
  const aggregator = AGGREGATOR_KP;
  const treasury = TREASURY_KP;
  const sender = Keypair.generate();
  const senderFeeRecipient = Keypair.generate();
  const refundAddress = Keypair.generate();

  // Token
  let mint: PublicKey;
  let senderTokenAccount: PublicKey;
  let vaultTokenAccount: PublicKey;

  // PDAs
  let configPda: PublicKey;
  let configBump: number;
  let vaultAuthorityPda: PublicKey;
  let vaultAuthorityBump: number;
  let tokenConfigPda: PublicKey;
  let senderStatePda: PublicKey;

  // Constants
  const MAX_BPS = 100_000;
  const PROVIDER_TO_AGGREGATOR_FX = 500; // 0.5%

  // Helper: derive order PDA from sender + nonce
  function orderPda(senderPubkey: PublicKey, nonce: number): PublicKey {
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(nonce));
    return PublicKey.findProgramAddressSync(
      [Buffer.from("order"), senderPubkey.toBuffer(), nonceBuf],
      program.programId
    )[0];
  }

  // Helper: get current nonce for sender
  async function getCurrentNonce(): Promise<number> {
    try {
      const state = await program.account.senderState.fetch(senderStatePda);
      return state.nonce.toNumber();
    } catch {
      return 0;
    }
  }

  before(async () => {
    // Airdrop to sender
    const sig = await connection.requestAirdrop(
      sender.publicKey,
      10 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(sig);

    // Derive PDAs
    [configPda, configBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      program.programId
    );
    [vaultAuthorityPda, vaultAuthorityBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault_authority")],
      program.programId
    );

    // Create mint
    mint = await createMint(
      connection,
      owner.payer,
      owner.publicKey,
      null,
      6 // 6 decimals (USDC-like)
    );

    // Derive token config PDA
    [tokenConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("token"), mint.toBuffer()],
      program.programId
    );

    // Derive vault PDA
    [vaultTokenAccount] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), mint.toBuffer()],
      program.programId
    );

    // Derive sender state PDA
    [senderStatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("nonce"), sender.publicKey.toBuffer()],
      program.programId
    );

    // Create sender token account and mint tokens
    senderTokenAccount = await createAccount(
      connection,
      owner.payer,
      mint,
      sender.publicKey
    );

    // Mint 1000 USDC to sender
    await mintTo(
      connection,
      owner.payer,
      mint,
      senderTokenAccount,
      owner.publicKey,
      1_000_000_000 // 1000 USDC (6 decimals)
    );

    // ─── Setup: Initialize protocol ──────────────────────────────────
    await program.methods
      .initialize()
      .accounts({
        owner: owner.publicKey,
        treasury: treasury.publicKey,
        aggregator: aggregator.publicKey,
      })
      .rpc();

    // ─── Setup: Support the token ────────────────────────────────────
    await program.methods
      .setTokenSupport(1)
      .accounts({
        mint: mint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    // ─── Setup: Set token fee settings ───────────────────────────────
    await program.methods
      .setTokenFeeSettings(
        new anchor.BN(60_000), // sender_to_provider: 60%
        new anchor.BN(10_000), // provider_to_aggregator: 10%
        new anchor.BN(5_000), // sender_to_aggregator: 5%
        new anchor.BN(PROVIDER_TO_AGGREGATOR_FX) // provider_to_aggregator_fx: 0.5%
      )
      .accounts({
        mint: mint,
      })
      .rpc();
  });

  it("creates an FX order successfully", async () => {
    const amount = new anchor.BN(100_000_000); // 100 USDC
    const rate = new anchor.BN(1_650); // NGN rate
    const senderFee = new anchor.BN(500_000); // 0.5 USDC
    const messageHash = Buffer.alloc(32, 1); // non-zero hash

    // Nonce is 0 for the first order
    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    const balanceBefore = await getAccount(connection, senderTokenAccount);

    await program.methods
      .createOrder(
        amount,
        rate,
        senderFee,
        Array.from(messageHash) as number[]
      )
      .accounts({
        sender: sender.publicKey,
        mint: mint,
        senderTokenAccount: senderTokenAccount,
        order: orderPdaKey,
        senderFeeRecipient: senderFeeRecipient.publicKey,
        refundAddress: refundAddress.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([sender])
      .rpc();

    // ─── Assertions ───────────────────────────────────────────────────

    // 1. Order account should exist with correct data
    const orderAccount = await program.account.order.fetch(orderPdaKey);
    assert.equal(
      orderAccount.sender.toBase58(),
      sender.publicKey.toBase58(),
      "sender mismatch"
    );
    assert.equal(
      orderAccount.token.toBase58(),
      mint.toBase58(),
      "token mismatch"
    );
    assert.equal(
      orderAccount.senderFeeRecipient.toBase58(),
      senderFeeRecipient.publicKey.toBase58(),
      "sender_fee_recipient mismatch"
    );
    assert.equal(
      orderAccount.senderFee.toNumber(),
      500_000,
      "sender_fee mismatch"
    );
    // protocol_fee = (100_000_000 * 500) / 100_000 = 500_000
    assert.equal(
      orderAccount.protocolFee.toNumber(),
      500_000,
      "protocol_fee mismatch"
    );
    assert.deepEqual(orderAccount.status, { pending: {} }, "status should be Pending");
    assert.equal(
      orderAccount.refundAddress.toBase58(),
      refundAddress.publicKey.toBase58(),
      "refund_address mismatch"
    );
    assert.equal(
      orderAccount.currentBps.toNumber(),
      MAX_BPS,
      "current_bps should be MAX_BPS"
    );
    assert.equal(
      orderAccount.initialAmount.toNumber(),
      100_000_000,
      "initial_amount mismatch"
    );
    assert.equal(
      orderAccount.currentAmount.toNumber(),
      100_000_000,
      "current_amount mismatch"
    );
    assert.equal(orderAccount.rate.toNumber(), 1_650, "rate mismatch");
    assert.equal(orderAccount.isLocal, false, "should not be local");

    // 2. Sender token balance should decrease by amount + sender_fee
    const balanceAfter = await getAccount(connection, senderTokenAccount);
    const expectedDeduction = BigInt(100_000_000 + 500_000);
    assert.equal(
      BigInt(balanceBefore.amount.toString()) - BigInt(balanceAfter.amount.toString()),
      expectedDeduction,
      "sender balance deduction mismatch"
    );

    // 3. Vault balance should increase by amount + sender_fee
    const vaultBalance = await getAccount(connection, vaultTokenAccount);
    assert.equal(
      BigInt(vaultBalance.amount.toString()),
      expectedDeduction,
      "vault balance mismatch"
    );

    // 4. Sender nonce should be 1
    const senderState = await program.account.senderState.fetch(senderStatePda);
    assert.equal(senderState.nonce.toNumber(), 1, "nonce should be 1");
  });

  it("creates a local order (rate=100) successfully", async () => {
    const amount = new anchor.BN(50_000_000); // 50 USDC
    const rate = new anchor.BN(100); // local
    const senderFee = new anchor.BN(1_000_000); // 1 USDC (required for local)
    const messageHash = Buffer.alloc(32, 2);

    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    await program.methods
      .createOrder(
        amount,
        rate,
        senderFee,
        Array.from(messageHash) as number[]
      )
      .accounts({
        sender: sender.publicKey,
        mint: mint,
        senderTokenAccount: senderTokenAccount,
        order: orderPdaKey,
        senderFeeRecipient: senderFeeRecipient.publicKey,
        refundAddress: refundAddress.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([sender])
      .rpc();

    const orderAccount = await program.account.order.fetch(orderPdaKey);
    assert.equal(orderAccount.protocolFee.toNumber(), 0, "local: protocol_fee should be 0");
    assert.equal(orderAccount.isLocal, true, "should be local");
    assert.equal(orderAccount.initialAmount.toNumber(), 50_000_000);

    // Nonce should now be 2
    const senderState = await program.account.senderState.fetch(senderStatePda);
    assert.equal(senderState.nonce.toNumber(), 2, "nonce should be 2");
  });

  it("fails when amount is zero", async () => {
    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    try {
      await program.methods
        .createOrder(
          new anchor.BN(0), // zero amount
          new anchor.BN(1_650),
          new anchor.BN(500_000),
          Array.from(Buffer.alloc(32, 1)) as number[]
        )
        .accounts({
          sender: sender.publicKey,
          mint: mint,
          senderTokenAccount: senderTokenAccount,
          order: orderPdaKey,
          senderFeeRecipient: senderFeeRecipient.publicKey,
          refundAddress: refundAddress.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([sender])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "AmountIsZero");
    }
  });

  it("fails when message_hash is all zeros", async () => {
    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    try {
      await program.methods
        .createOrder(
          new anchor.BN(100_000_000),
          new anchor.BN(1_650),
          new anchor.BN(500_000),
          Array.from(Buffer.alloc(32, 0)) as number[] // all zeros
        )
        .accounts({
          sender: sender.publicKey,
          mint: mint,
          senderTokenAccount: senderTokenAccount,
          order: orderPdaKey,
          senderFeeRecipient: senderFeeRecipient.publicKey,
          refundAddress: refundAddress.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([sender])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "InvalidMessageHash");
    }
  });

  it("fails when local transfer has sender_fee=0", async () => {
    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    try {
      await program.methods
        .createOrder(
          new anchor.BN(50_000_000),
          new anchor.BN(100), // local
          new anchor.BN(0), // zero sender_fee — should fail
          Array.from(Buffer.alloc(32, 1)) as number[]
        )
        .accounts({
          sender: sender.publicKey,
          mint: mint,
          senderTokenAccount: senderTokenAccount,
          order: orderPdaKey,
          senderFeeRecipient: senderFeeRecipient.publicKey,
          refundAddress: refundAddress.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([sender])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "SenderFeeIsZero");
    }
  });

  it("fails when protocol is paused", async () => {
    // Pause the protocol
    await program.methods.pause().accounts({
      owner: owner.publicKey,
      config: configPda,
    }).rpc();

    const nonce = await getCurrentNonce();
    const orderPdaKey = orderPda(sender.publicKey, nonce);

    try {
      await program.methods
        .createOrder(
          new anchor.BN(100_000_000),
          new anchor.BN(1_650),
          new anchor.BN(500_000),
          Array.from(Buffer.alloc(32, 1)) as number[]
        )
        .accounts({
          sender: sender.publicKey,
          mint: mint,
          senderTokenAccount: senderTokenAccount,
          order: orderPdaKey,
          senderFeeRecipient: senderFeeRecipient.publicKey,
          refundAddress: refundAddress.publicKey,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([sender])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "ProtocolPaused");
    }

    // Unpause for other tests
    await program.methods.unpause().accounts({
      owner: owner.publicKey,
      config: configPda,
    }).rpc();
  });
});
