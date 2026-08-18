import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import {
  assertDeployerEnvironment,
  confirmContinue,
  encodeSetTokenFeeSettings,
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

async function setTokenFeeSettings() {
  console.log("\n=== Configuring Token Fee Settings on Paycrest Gateway ===");
  console.log(`Network: ${network}\n`);
  console.log("Note: run 'npm run set-tokens' first — a token must already be");
  console.log("whitelisted (TokenConfig PDA must exist) before its fee settings can be set.\n");

  const programId = getProgramId(network);
  const owner = getDeployerKeypair();
  const [configPda] = findConfigPda(programId);
  const networkConfig = getNetworkConfig(network);
  const tokens = Object.entries(networkConfig.supportedTokens);

  await confirmContinue({
    Network: network,
    "Program Id": programId.toBase58(),
    Owner: owner.publicKey.toBase58(),
    Tokens: tokens
      .map(([name, t]) => `${name}: sender=${t.senderToTreasury}bps provider=${t.providerToTreasury}bps`)
      .join(", "),
  });

  const connection = getConnection(network);

  for (const [name, token] of tokens) {
    const mint = new PublicKey(token.mint);
    const [tokenConfigPda] = findTokenConfigPda(programId, mint);

    console.log(`\nSetting fee settings for ${name} (${mint.toBase58()})...`);
    console.log(`   senderToTreasury: ${token.senderToTreasury} bps`);
    console.log(`   providerToTreasury: ${token.providerToTreasury} bps`);

    const ix = new TransactionInstruction({
      programId,
      keys: [
        { pubkey: owner.publicKey, isSigner: true, isWritable: false },
        { pubkey: configPda, isSigner: false, isWritable: false },
        { pubkey: tokenConfigPda, isSigner: false, isWritable: true },
      ],
      data: encodeSetTokenFeeSettings(token.senderToTreasury, token.providerToTreasury),
    });

    await sendAndConfirm(connection, network, ix, owner);
    console.log(`   ${name} fee settings updated.`);
  }

  console.log("\n=== All token fee settings configured! ===");
}

setTokenFeeSettings()
  .then(() => {
    console.log("\nDone!");
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
