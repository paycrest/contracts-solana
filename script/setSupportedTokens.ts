import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  assertDeployerEnvironment,
  confirmContinue,
  encodeSetTokenSupport,
  findConfigPda,
  findTokenConfigPda,
  getConnection,
  getDeployerKeypair,
  getProgramId,
  sendAndConfirm,
} from "./utils";
import { getNetworkConfig } from "./config";
import dotenv from "dotenv";

dotenv.config();

const network = process.argv[2] || "devnet";

assertDeployerEnvironment();

async function setSupportedTokens() {
  console.log("\n=== Whitelisting Tokens on Paycrest Gateway ===");
  console.log(`Network: ${network}\n`);

  const programId = getProgramId(network);
  const owner = getDeployerKeypair();
  const [configPda] = findConfigPda(programId);
  const networkConfig = getNetworkConfig(network);
  const tokens = Object.entries(networkConfig.supportedTokens);

  await confirmContinue({
    Network: network,
    "Program Id": programId.toBase58(),
    Owner: owner.publicKey.toBase58(),
    Tokens: tokens.map(([name, t]) => `${name} (${t.mint})`).join(", "),
  });

  const connection = getConnection(network);

  for (const [name, token] of tokens) {
    const mint = new PublicKey(token.mint);
    const [tokenConfigPda, bump] = findTokenConfigPda(programId, mint);

    console.log(`\nWhitelisting ${name} (${mint.toBase58()})...`);
    console.log(`   TokenConfig PDA: ${tokenConfigPda.toBase58()} (bump ${bump})`);

    const ix = new TransactionInstruction({
      programId,
      keys: [
        { pubkey: owner.publicKey, isSigner: true, isWritable: true },
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: tokenConfigPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: encodeSetTokenSupport(bump, true),
    });

    await sendAndConfirm(connection, network, ix, owner);
    console.log(`   ${name} whitelisted.`);
  }

  console.log("\n=== All tokens whitelisted! ===");
  console.log("Run 'npm run set-fee-settings' next to configure fee BPS per token.");
}

setSupportedTokens()
  .then(() => {
    console.log("\nDone!");
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
