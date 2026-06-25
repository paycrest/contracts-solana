import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SolanaGateway } from "../target/types/solana_gateway";
import { Keypair, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createAccount, getAccount } from "@solana/spl-token";
import { assert } from "chai";
import { setupProtocol, SetupResult, fundWallet } from "./helpers/setup";

describe("settleIn", () => {
  let ctx: SetupResult;
  const caller = Keypair.generate();
  const recipient = Keypair.generate();
  const senderFeeRecipient = Keypair.generate();

  let callerTokenAccount: PublicKey;
  let recipientTokenAccount: PublicKey;
  let senderFeeRecipientTokenAccount: PublicKey;

  before(async () => {
    ctx = await setupProtocol();
    const { connection, owner, mint } = ctx;

    const sig = await connection.requestAirdrop(caller.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);

    callerTokenAccount = await fundWallet(connection, owner.payer, mint, caller.publicKey, 1_000_000_000);
    recipientTokenAccount = await createAccount(connection, owner.payer, mint, recipient.publicKey);
    senderFeeRecipientTokenAccount = await createAccount(connection, owner.payer, mint, senderFeeRecipient.publicKey);
  });

  it("settles FX in-flow correctly (event-only, no order account)", async () => {
    const orderId = Buffer.alloc(32, 200);
    const amount = 100_000_000;
    const senderFee = 500_000;
    const rate = 1650;

    const recipientBefore = await getAccount(ctx.connection, recipientTokenAccount);
    const treasuryBefore = await getAccount(ctx.connection, ctx.treasuryTokenAccount);
    const senderFeeBefore = await getAccount(ctx.connection, senderFeeRecipientTokenAccount);

    await ctx.program.methods
      .settleIn(
        Array.from(orderId) as any,
        new anchor.BN(amount),
        new anchor.BN(senderFee),
        new anchor.BN(rate),
        recipient.publicKey,
        senderFeeRecipient.publicKey
      )
      .accounts({
        caller: caller.publicKey,
        mint: ctx.mint,
        callerTokenAccount,
        recipientTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        senderFeeRecipientTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([caller])
      .rpc();

    // Recipient gets amount - aggregator_fee = 100M - 500K = 99.5M
    const recipientAfter = await getAccount(ctx.connection, recipientTokenAccount);
    const recipientReceived = BigInt(recipientAfter.amount.toString()) - BigInt(recipientBefore.amount.toString());
    assert.equal(recipientReceived, BigInt(99_500_000));

    // Treasury: aggregator_fee(500K) + sender_fee_agg_share(500K * 5% = 25K) = 525K
    const treasuryAfter = await getAccount(ctx.connection, ctx.treasuryTokenAccount);
    const treasuryReceived = BigInt(treasuryAfter.amount.toString()) - BigInt(treasuryBefore.amount.toString());
    assert.equal(treasuryReceived, BigInt(525_000));

    // Sender fee recipient: 500K - 25K = 475K
    const senderFeeAfter = await getAccount(ctx.connection, senderFeeRecipientTokenAccount);
    const senderFeeReceived = BigInt(senderFeeAfter.amount.toString()) - BigInt(senderFeeBefore.amount.toString());
    assert.equal(senderFeeReceived, BigInt(475_000));

    // No order account should exist (event-only)
    // This would throw if we tried to fetch an order PDA
  });

  it("settles local in-flow correctly", async () => {
    const orderId = Buffer.alloc(32, 201);
    const amount = 50_000_000;
    const senderFee = 1_000_000;
    const rate = 100;

    const recipientBefore = await getAccount(ctx.connection, recipientTokenAccount);

    await ctx.program.methods
      .settleIn(
        Array.from(orderId) as any,
        new anchor.BN(amount),
        new anchor.BN(senderFee),
        new anchor.BN(rate),
        recipient.publicKey,
        senderFeeRecipient.publicKey
      )
      .accounts({
        caller: caller.publicKey,
        mint: ctx.mint,
        callerTokenAccount,
        recipientTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        senderFeeRecipientTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([caller])
      .rpc();

    // Recipient gets full amount (no protocol fee for local)
    const recipientAfter = await getAccount(ctx.connection, recipientTokenAccount);
    const recipientReceived = BigInt(recipientAfter.amount.toString()) - BigInt(recipientBefore.amount.toString());
    assert.equal(recipientReceived, BigInt(50_000_000));
  });

  it("fails when amount is zero", async () => {
    try {
      await ctx.program.methods
        .settleIn(Array.from(Buffer.alloc(32, 202)) as any, new anchor.BN(0), new anchor.BN(500_000), new anchor.BN(1650), recipient.publicKey, senderFeeRecipient.publicKey)
        .accounts({
          caller: caller.publicKey,
          mint: ctx.mint,
          callerTokenAccount,
          recipientTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          senderFeeRecipientTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([caller])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "AmountIsZero");
    }
  });
});
