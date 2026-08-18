/**
 * Submit a devnet/mainnet `create_order` against the Paycrest Gateway program.
 * Uses a legacy (v0-less) transaction — fine for short test message hashes.
 * For max-size X25519 blobs use v0 + ALT (Phase 5 / Nobblocks).
 */
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import bs58 from "bs58";
import dotenv from "dotenv";
import { getNetworkConfig } from "./config";
import {
  TOKEN_PROGRAM_ID,
  decodeConfig,
  encodeCreateOrder,
  findConfigPda,
  findNextFreeNonce,
  findTokenConfigPda,
  findVaultAuthorityPda,
  getConnection,
  getExplorerUrl,
  getProgramId,
  orderIdHash,
} from "./utils";

dotenv.config();

const network = process.argv[2] || "devnet";

function loadKeypair(envName: string, fallback?: Keypair): Keypair {
  const raw = process.env[envName]?.trim();
  if (!raw) {
    if (fallback) return fallback;
    throw new Error(`Missing ${envName} in .env (base58 secret or JSON byte array)`);
  }
  if (raw.startsWith("[")) {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(raw)));
  }
  return Keypair.fromSecretKey(bs58.decode(raw));
}

function parseMessageHash(): Buffer {
  const raw = process.env.SOLANA_MESSAGE_HASH?.trim() || "paycrest-solana-test-v1";
  if (raw.startsWith("0x")) {
    return Buffer.from(raw.slice(2), "hex");
  }
  if (/^[A-Za-z0-9+/=]+$/.test(raw) && raw.length > 16) {
    try {
      return Buffer.from(raw, "base64");
    } catch {
      /* fall through */
    }
  }
  return Buffer.from(raw, "utf8");
}

async function main() {
  console.log("\n=== Paycrest Gateway create_order ===");
  console.log(`Network: ${network}\n`);

  const programId = getProgramId(network);
  const connection = getConnection(network);
  const networkConfig = getNetworkConfig(network);

  const depositor = loadKeypair("SOLANA_DEPOSITOR_PRIVATE_KEY");
  const feePayer = process.env.SOLANA_FEE_PAYER_PRIVATE_KEY
    ? loadKeypair("SOLANA_FEE_PAYER_PRIVATE_KEY")
    : depositor;

  const mintName = process.env.SOLANA_TOKEN || "USDC";
  const tokenEntry = networkConfig.supportedTokens[mintName];
  if (!tokenEntry) {
    throw new Error(`Unknown SOLANA_TOKEN=${mintName}; check script/config.ts`);
  }
  const mint = new PublicKey(tokenEntry.mint);

  const amountHuman = process.env.SOLANA_CREATE_ORDER_AMOUNT || "0.01";
  const amount = BigInt(Math.round(parseFloat(amountHuman) * 1_000_000)); // 6 dp USDC

  const rate = BigInt(process.env.SOLANA_CREATE_ORDER_RATE || "12457");
  const senderFee = BigInt(process.env.SOLANA_CREATE_ORDER_SENDER_FEE || "0");

  const refundPubkey = process.env.SOLANA_REFUND_ADDRESS
    ? new PublicKey(process.env.SOLANA_REFUND_ADDRESS)
    : depositor.publicKey;

  const senderFeeRecipient =
    senderFee > 0n && process.env.SOLANA_SENDER_FEE_RECIPIENT
      ? new PublicKey(process.env.SOLANA_SENDER_FEE_RECIPIENT)
      : PublicKey.default;

  const messageHash = parseMessageHash();

  const [configPda] = findConfigPda(programId);
  const configAccount = await connection.getAccountInfo(configPda);
  if (!configAccount) {
    throw new Error("Config PDA missing — run npm run deploy");
  }
  const config = decodeConfig(configAccount.data);
  if (config.paused) {
    throw new Error("Gateway is paused");
  }
  const chainId = config.chainId;

  const [tokenConfigPda] = findTokenConfigPda(programId, mint);
  const [vaultAuthority, vaultBump] = findVaultAuthorityPda(programId);
  const vaultAta = getAssociatedTokenAddressSync(mint, vaultAuthority, true, TOKEN_PROGRAM_ID);

  const { nonce, orderPda, orderBump } = await findNextFreeNonce(
    connection,
    programId,
    depositor.publicKey,
    chainId
  );
  const orderId = orderIdHash(depositor.publicKey, nonce, chainId);

  const depositorAta = getAssociatedTokenAddressSync(mint, depositor.publicKey, false, TOKEN_PROGRAM_ID);
  const refundAta = getAssociatedTokenAddressSync(mint, refundPubkey, false, TOKEN_PROGRAM_ID);

  console.log("Parameters:");
  console.log(`  Program       : ${programId.toBase58()}`);
  console.log(`  Depositor     : ${depositor.publicKey.toBase58()}`);
  console.log(`  Fee payer     : ${feePayer.publicKey.toBase58()}`);
  console.log(`  Mint          : ${mint.toBase58()} (${mintName})`);
  console.log(`  Amount        : ${amountHuman} (${amount} base units)`);
  console.log(`  Rate (packed) : ${rate}`);
  console.log(`  Nonce         : ${nonce}`);
  console.log(`  Order PDA     : ${orderPda.toBase58()}`);
  console.log(`  Order id      : 0x${orderId.toString("hex")}`);
  console.log(`  Refund        : ${refundPubkey.toBase58()}`);
  console.log(`  Message (${messageHash.length} B): ${messageHash.toString("base64")}`);

  const tx = new Transaction();

  // Vault ATA (one-time per mint) — fee payer funds rent if missing.
  const vaultInfo = await connection.getAccountInfo(vaultAta);
  if (!vaultInfo) {
    console.log("\nCreating vault ATA (first use for this mint)...");
    tx.add(
      createAssociatedTokenAccountIdempotentInstruction(
        feePayer.publicKey,
        vaultAta,
        vaultAuthority,
        mint,
        TOKEN_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      )
    );
  }

  // D10: refund ATA must exist before create_order.
  tx.add(
    createAssociatedTokenAccountIdempotentInstruction(
      feePayer.publicKey,
      refundAta,
      refundPubkey,
      mint,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    )
  );

  const ix = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: feePayer.publicKey, isSigner: true, isWritable: true },
      { pubkey: depositor.publicKey, isSigner: true, isWritable: false },
      { pubkey: depositorAta, isSigner: false, isWritable: true },
      { pubkey: orderPda, isSigner: false, isWritable: true },
      { pubkey: vaultAta, isSigner: false, isWritable: true },
      { pubkey: configPda, isSigner: false, isWritable: false },
      { pubkey: tokenConfigPda, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: refundAta, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: encodeCreateOrder({
      orderBump,
      vaultBump,
      nonce,
      amount,
      rate,
      senderFee,
      senderFeeRecipient,
      refundAddress: refundPubkey,
      messageHash,
    }),
  });
  tx.add(ix);

  console.log("\nSubmitting transaction...");
  const signature = await sendAndConfirmTransaction(
    connection,
    tx,
    [feePayer, depositor],
    { commitment: "confirmed" }
  );

  console.log("\n=== create_order SUCCESS ===");
  console.log(`Signature : ${signature}`);
  console.log(`Explorer  : ${getExplorerUrl(network, signature)}`);
  const fs = await import("fs");
  const os = await import("os");
  const sigPath = `${os.tmpdir()}/paycrest-solana-last-sig.txt`;
  fs.writeFileSync(sigPath, signature, "utf8");
  console.log(`\nSaved signature → ${sigPath}`);
  console.log("\nNext: decode + index with solanatool from test/:");
  console.log(`  go run ./solanatool decode-tx ${signature}`);
  console.log(`  go run ./solanatool index-tx ${signature}   # needs aggregator + solana-devnet network row`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
