import * as anchor from "@anchor-lang/core";
import { Keypair, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createAccount, getAccount } from "@solana/spl-token";
import { assert } from "chai";
import { setupProtocol, SetupResult, fundWallet, AGGREGATOR_KP } from "./helpers/setup";

describe("refund", () => {
  let ctx: SetupResult;
  const sender = Keypair.generate();
  const senderFeeRecipient = Keypair.generate();
  const refundAddress = Keypair.generate();

  let senderTokenAccount: PublicKey;
  let refundTokenAccount: PublicKey;
  let senderFeeRecipientTokenAccount: PublicKey;

  before(async () => {
    ctx = await setupProtocol();
    const { connection, owner, mint } = ctx;

    const sig = await connection.requestAirdrop(sender.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);

    senderTokenAccount = await fundWallet(connection, owner.payer, mint, sender.publicKey, 1_000_000_000);
    refundTokenAccount = await createAccount(connection, owner.payer, mint, refundAddress.publicKey);
    senderFeeRecipientTokenAccount = await createAccount(connection, owner.payer, mint, senderFeeRecipient.publicKey);
  });

  async function createTestOrder(amount: number, rate: number, senderFee: number): Promise<PublicKey> {
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

    return orderPda;
  }

  it("refunds an order with zero fee", async () => {
    const orderPda = await createTestOrder(100_000_000, 1650, 500_000);

    const refundBefore = await getAccount(ctx.connection, refundTokenAccount);

    await ctx.program.methods
      .refund(new anchor.BN(0))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        refundTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    const orderAccount = await ctx.program.account.order.fetch(orderPda);
    assert.deepEqual(orderAccount.status, { refunded: {} });
    assert.equal(orderAccount.currentBps.toNumber(), 0);
    assert.equal(orderAccount.currentAmount.toNumber(), 0);

    // refund_amount = current_amount - fee + remaining_sender_fee = 100M - 0 + 500K = 100.5M
    const refundAfter = await getAccount(ctx.connection, refundTokenAccount);
    const received = BigInt(refundAfter.amount.toString()) - BigInt(refundBefore.amount.toString());
    assert.equal(received, BigInt(100_500_000));
  });

  it("refunds with fee deducted to treasury", async () => {
    const orderPda = await createTestOrder(80_000_000, 1650, 400_000);
    // protocol_fee = 80M * 500 / 100K = 400_000
    const fee = 200_000; // half of protocol_fee

    const treasuryBefore = await getAccount(ctx.connection, ctx.treasuryTokenAccount);
    const refundBefore = await getAccount(ctx.connection, refundTokenAccount);

    await ctx.program.methods
      .refund(new anchor.BN(fee))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        refundTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    // Treasury gets fee
    const treasuryAfter = await getAccount(ctx.connection, ctx.treasuryTokenAccount);
    const treasuryGot = BigInt(treasuryAfter.amount.toString()) - BigInt(treasuryBefore.amount.toString());
    assert.equal(treasuryGot, BigInt(fee));

    // Refund = 80M - 200K + 400K = 80.2M
    const refundAfter = await getAccount(ctx.connection, refundTokenAccount);
    const refundGot = BigInt(refundAfter.amount.toString()) - BigInt(refundBefore.amount.toString());
    assert.equal(refundGot, BigInt(80_200_000));
  });

  it("fails when non-aggregator tries to refund", async () => {
    const orderPda = await createTestOrder(50_000_000, 1650, 250_000);
    const fakeAgg = Keypair.generate();
    const sig = await ctx.connection.requestAirdrop(fakeAgg.publicKey, LAMPORTS_PER_SOL);
    await ctx.connection.confirmTransaction(sig);

    try {
      await ctx.program.methods
        .refund(new anchor.BN(0))
        .accounts({
          aggregator: fakeAgg.publicKey,
          order: orderPda,
          mint: ctx.mint,
          refundTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([fakeAgg])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "ConstraintHasOne");
    }
  });

  it("fails when fee exceeds protocol_fee", async () => {
    const orderPda = await createTestOrder(50_000_000, 1650, 250_000);
    // protocol_fee = 50M * 500 / 100K = 250_000

    try {
      await ctx.program.methods
        .refund(new anchor.BN(999_999)) // way more than 250K
        .accounts({
          aggregator: AGGREGATOR_KP.publicKey,
          order: orderPda,
          mint: ctx.mint,
          refundTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([AGGREGATOR_KP])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "FeeExceedsProtocolFee");
    }
  });

  it("fails when order already refunded", async () => {
    const orderPda = await createTestOrder(30_000_000, 1650, 150_000);

    // Refund first time
    await ctx.program.methods
      .refund(new anchor.BN(0))
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
        mint: ctx.mint,
        refundTokenAccount,
        treasuryTokenAccount: ctx.treasuryTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    // Try again
    try {
      await ctx.program.methods
        .refund(new anchor.BN(0))
        .accounts({
          aggregator: AGGREGATOR_KP.publicKey,
          order: orderPda,
          mint: ctx.mint,
          refundTokenAccount,
          treasuryTokenAccount: ctx.treasuryTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([AGGREGATOR_KP])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "OrderRefunded");
    }
  });
});
