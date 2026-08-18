/** Create the gateway vault ATA for a mint if it does not exist yet. */
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createAssociatedTokenAccountIdempotentInstruction,
  getAssociatedTokenAddressSync,
} from "@solana/spl-token";
import { PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import dotenv from "dotenv";
import { getNetworkConfig } from "./config";
import {
  TOKEN_PROGRAM_ID,
  findVaultAuthorityPda,
  getConnection,
  getDeployerKeypair,
  getExplorerUrl,
  getProgramId,
} from "./utils";

dotenv.config();

const network = process.argv[2] || "devnet";
const mintName = process.argv[3] || process.env.SOLANA_TOKEN || "USDC";

async function main() {
  const programId = getProgramId(network);
  const connection = getConnection(network);
  const payer = getDeployerKeypair();
  const tokenEntry = getNetworkConfig(network).supportedTokens[mintName];
  if (!tokenEntry) {
    throw new Error(`Unknown mint ${mintName}`);
  }
  const mint = new PublicKey(tokenEntry.mint);
  const [vaultAuthority] = findVaultAuthorityPda(programId);
  const vaultAta = getAssociatedTokenAddressSync(mint, vaultAuthority, true, TOKEN_PROGRAM_ID);

  const tx = new Transaction().add(
    createAssociatedTokenAccountIdempotentInstruction(
      payer.publicKey,
      vaultAta,
      vaultAuthority,
      mint,
      TOKEN_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    )
  );

  const sig = await sendAndConfirmTransaction(connection, tx, [payer], { commitment: "confirmed" });
  console.log(`Vault ATA: ${vaultAta.toBase58()}`);
  console.log(`Signature: ${sig}`);
  console.log(getExplorerUrl(network, sig));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
