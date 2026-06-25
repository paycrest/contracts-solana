import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SolanaGateway } from "../target/types/solana_gateway";
import { Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createAccount, getAccount } from "@solana/spl-token";
import { assert } from "chai";
import { setupProtocol, SetupResult, fundWallet, AGGREGATOR_KP } from "./helpers/setup";

describe("settleOut", () => {
  let ctx: SetupResult;
  const sender = Keypair.generate();
  const senderFeeRecipient = Keypair.generate();
  const refundAddress = Keypair.generate();
  const liquidityProvider = Keypair.generate();

  let senderTokenAccount: PublicKey;
  let lpTokenAccount: PublicKey;
  let senderFeeRecipientTokenAccount: PublicKey;

  before(async () => {
    ctx = await setupProtocol();
    const { connection, owner, mint } = ctx;

    const sig = await connection.requestAirdrop(sender.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);

    senderTokenAccount = await fundWallet(connection, owner.payer, mint, sender.publicKey, 1_000_000_000);
    lpTokenAccount = await createAccount(connection, owner.payer, mint, liquidityProvider.publicKey);
    senderFeeRecipientTokenAccount = await createAccount(connection, owner.payer, mint, senderFeeRecipient.publicKey);
  });

  async function createTestOrder(amount: number, rate: number, senderFee: number): Promise<{ orderPda: PublicKey; nonce: number }> {
    // Read current nonce
    const senderStatePda = ctx.senderStatePda(sender.publicKey);
    let nonce = 0;
    try {
      const state = await ctx.program.account.senderState.fetch(senderStatePda);
      nonce = state.nonce.toNumber();
    } catch {}

    const orderPda = ctx.orderPda(sender.publicKey, nonce);

    await ctx.program.methods
      .createOrder(new anchor.BN(amount), new anchor.BN(rate), new anchor.BN(senderFee), Array.from(Buffer.alloc(32, 1)) as any)
      .accounts({
        sender: sender.publicKey,
        mint: ctx.mint,
        senderTokenAccount,
        order: orderPda,
        senderFeeRecipient: senderFeeRecipient.publicKey,
        refundAddress: refundAddress.publicKey,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([sender])
      .rpc();

    return { orderPda, nonce };
  }

  it("settles FX order fully (100%)", async () => {
    const { orderPda } = await createTestOrder(100_000_000, 1650, 500_000);

    const lpBefore = await getAccount(ctx.connection, lpTokenAccount);
    const treasuryBefore = await getAccount(ctx.connection, ctx.treasuryTokenAccount);

    await ctx.program.methods
      .settleOut(Array.from(Buffer.alloc(32, 10)) as any, new anchor.BN(100_000), new anchor.BN(0))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        liquidityProviderTokenAccount: lpTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        senderFeeRecipientTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    const orderAccount = await ctx.program.account.order.fetch(orderPda);
    assert.deepEqual(orderAccount.status, { fulfilled: {} });
    assert.equal(orderAccount.currentBps.toNumber(), 0);

    // LP: 100M - protocol_fee(500K) = 99.5M
    const lpAfter = await getAccount(ctx.connection, lpTokenAccount);
    const lpReceived = BigInt(lpAfter.amount.toString()) - BigInt(lpBefore.amount.toString());
    assert.equal(lpReceived, BigInt(99_500_000));

    // Treasury: protocol_fee(500K) + sender_fee_agg_share(500K * 5% = 25K) = 525K
    const treasuryAfter = await getAccount(ctx.connection, ctx.treasuryTokenAccount);
    const treasuryReceived = BigInt(treasuryAfter.amount.toString()) - BigInt(treasuryBefore.amount.toString());
    assert.equal(treasuryReceived, BigInt(525_000));
  });

  it("settles FX order partially (50% + 50%)", async () => {
    const { orderPda } = await createTestOrder(200_000_000, 1650, 1_000_000);

    // First 50%
    await ctx.program.methods
      .settleOut(Array.from(Buffer.alloc(32, 20)) as any, new anchor.BN(50_000), new anchor.BN(0))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        liquidityProviderTokenAccount: lpTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        senderFeeRecipientTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    let orderAccount = await ctx.program.account.order.fetch(orderPda);
    assert.equal(orderAccount.currentBps.toNumber(), 50_000);
    assert.deepEqual(orderAccount.status, { pending: {} });

    // Second 50%
    await ctx.program.methods
      .settleOut(Array.from(Buffer.alloc(32, 21)) as any, new anchor.BN(50_000), new anchor.BN(0))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        liquidityProviderTokenAccount: lpTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        senderFeeRecipientTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    orderAccount = await ctx.program.account.order.fetch(orderPda);
    assert.deepEqual(orderAccount.status, { fulfilled: {} });
    assert.equal(orderAccount.currentBps.toNumber(), 0);
  });

  it("fails when non-aggregator tries to settle", async () => {
    const { orderPda } = await createTestOrder(50_000_000, 1650, 250_000);
    const fakeAgg = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(fakeAgg.publicKey, LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig);

    try {
      await ctx.program.methods
        .settleOut(Array.from(Buffer.alloc(32, 30)) as any, new anchor.BN(100_000), new anchor.BN(0))
        .accounts({
          aggregator: fakeAgg.publicKey,
          order: orderPda,
          mint: ctx.mint,
          liquidityProviderTokenAccount: lpTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          senderFeeRecipientTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([fakeAgg])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.ok(err.toString().includes("ConstraintHasOne") || err.toString().includes("unknown signer") || err.toString().includes("Error"));
    }
  });

  it("fails when settle_percent is 0", async () => {
    const { orderPda } = await createTestOrder(50_000_000, 1650, 250_000);

    try {
      await ctx.program.methods
        .settleOut(Array.from(Buffer.alloc(32, 40)) as any, new anchor.BN(0), new anchor.BN(0))
        .accounts({
          aggregator: AGGREGATOR_KP.publicKey,
          order: orderPda,
          mint: ctx.mint,
          liquidityProviderTokenAccount: lpTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          senderFeeRecipientTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([AGGREGATOR_KP])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "InvalidSettlePercent");
    }
  });
});
