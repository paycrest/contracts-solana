import * as anchor from "@anchor-lang/core";
import { Keypair, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createAccount } from "@solana/spl-token";
import { assert } from "chai";
import { setupProtocol, SetupResult, fundWallet, AGGREGATOR_KP } from "./helpers/setup";

describe("closeOrder", () => {
  let ctx: SetupResult;
  const sender = Keypair.generate();
  const senderFeeRecipient = Keypair.generate();
  const refundAddress = Keypair.generate();
  const liquidityProvider = Keypair.generate();

  let senderTokenAccount: PublicKey;
  let lpTokenAccount: PublicKey;
  let refundTokenAccount: PublicKey;
  let senderFeeRecipientTokenAccount: PublicKey;

  before(async () => {
    ctx = await setupProtocol();
    const { connection, owner, mint } = ctx;

    const sig = await connection.requestAirdrop(sender.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);

    senderTokenAccount = await fundWallet(connection, owner.payer, mint, sender.publicKey, 1_000_000_000);
    lpTokenAccount = await createAccount(connection, owner.payer, mint, liquidityProvider.publicKey);
    refundTokenAccount = await createAccount(connection, owner.payer, mint, refundAddress.publicKey);
    senderFeeRecipientTokenAccount = await createAccount(connection, owner.payer, mint, senderFeeRecipient.publicKey);
  });

  async function createAndSettleOrder(): Promise<PublicKey> {
    const senderStatePda = ctx.senderStatePda(sender.publicKey);
    let nonce = 0;
    try {
      const state = await ctx.program.account.senderState.fetch(senderStatePda);
      nonce = state.nonce.toNumber();
    } catch {}
    const orderPda = ctx.orderPda(sender.publicKey, nonce);

    await ctx.program.methods
      .createOrder(new anchor.BN(10_000_000), new anchor.BN(1650), new anchor.BN(50_000), Array.from(Buffer.alloc(32, 1)) as any)
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

    // Settle fully
    await ctx.program.methods
      .settleOut(Array.from(Buffer.alloc(32, 99)) as any, new anchor.BN(100_000), new anchor.BN(0))
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

    return orderPda;
  }

  it("closes a fulfilled order and reclaims rent to aggregator", async () => {
    const orderPda = await createAndSettleOrder();

    // Verify order is fulfilled
    const orderAccount = await ctx.program.account.order.fetch(orderPda);
    assert.deepEqual(orderAccount.status, { fulfilled: {} });

    const aggBefore = await ctx.connection.getBalance(AGGREGATOR_KP.publicKey);

    await ctx.program.methods
      .closeOrder()
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    // Order account should no longer exist
    const orderInfo = await ctx.connection.getAccountInfo(orderPda);
    assert.isNull(orderInfo, "Order account should be closed");

    // Aggregator should have received rent
    const aggAfter = await ctx.connection.getBalance(AGGREGATOR_KP.publicKey);
    assert.isTrue(aggAfter > aggBefore, "Aggregator should receive rent");
  });

  it("fails when order is still Pending", async () => {
    const senderStatePda = ctx.senderStatePda(sender.publicKey);
    let nonce = 0;
    try {
      const state = await ctx.program.account.senderState.fetch(senderStatePda);
      nonce = state.nonce.toNumber();
    } catch {}
    const orderPda = ctx.orderPda(sender.publicKey, nonce);

    // Create but don't settle
    await ctx.program.methods
      .createOrder(new anchor.BN(5_000_000), new anchor.BN(1650), new anchor.BN(25_000), Array.from(Buffer.alloc(32, 2)) as any)
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

    try {
      await ctx.program.methods
        .closeOrder()
        .accounts({
          aggregator: AGGREGATOR_KP.publicKey,
          order: orderPda,
        })
        .signers([AGGREGATOR_KP])
        .rpc();
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.include(err.toString(), "OrderNotTerminal");
    }
  });

  it("closes a refunded order", async () => {
    const senderStatePda = ctx.senderStatePda(sender.publicKey);
    let nonce = 0;
    try {
      const state = await ctx.program.account.senderState.fetch(senderStatePda);
      nonce = state.nonce.toNumber();
    } catch {}
    const orderPda = ctx.orderPda(sender.publicKey, nonce);

    await ctx.program.methods
      .createOrder(new anchor.BN(5_000_000), new anchor.BN(1650), new anchor.BN(25_000), Array.from(Buffer.alloc(32, 3)) as any)
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

    // Refund it
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

    // Now close
    await ctx.program.methods
      .closeOrder()
      .accounts({
        aggregator: AGGREGATOR_KP.publicKey,
        order: orderPda,
      })
      .signers([AGGREGATOR_KP])
      .rpc();

    const orderInfo = await ctx.connection.getAccountInfo(orderPda);
    assert.isNull(orderInfo, "Refunded order should be closed");
  });
});
