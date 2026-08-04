import { PublicKey } from "@solana/web3.js";
import {
  decodeConfig,
  decodeTokenConfig,
  findConfigPda,
  findTokenConfigPda,
  formatAddress,
  getAccountExplorerUrl,
  getConnection,
  getProgramId,
} from "./utils";
import { getNetworkConfig } from "./config";
import dotenv from "dotenv";

dotenv.config();

const network = process.argv[2] || "devnet";

async function checkStatus() {
  console.log("\nChecking Gateway Program Status");
  console.log(`Network: ${network}\n`);

  const networkConfig = getNetworkConfig(network);

  let programId: PublicKey;
  try {
    programId = getProgramId(network);
  } catch {
    console.log("No program id configured for this network yet.");
    console.log("Run 'npm run deploy' to deploy the program first.\n");
    return;
  }

  const connection = getConnection(network);

  console.log("Program Information:");
  console.log(`   Program Id: ${programId.toBase58()}`);
  console.log(`   Explorer: ${getAccountExplorerUrl(network, programId.toBase58())}\n`);

  const [configPda] = findConfigPda(programId);
  const configAccount = await connection.getAccountInfo(configPda);

  if (!configAccount) {
    console.log("Config PDA not found — program is deployed but not yet initialized.");
    console.log("Run 'npm run deploy' again or send the initialize instruction directly.\n");
    return;
  }

  const config = decodeConfig(configAccount.data);

  console.log("Config:");
  console.log(`   Config PDA: ${configPda.toBase58()}`);
  console.log(`   Owner: ${formatAddress(config.owner.toBase58())}`);
  console.log(
    `   Pending Owner: ${config.pendingOwner.equals(PublicKey.default) ? "(none)" : formatAddress(config.pendingOwner.toBase58())}`
  );
  console.log(
    `   Treasury: ${config.treasury.equals(PublicKey.default) ? "(not set)" : formatAddress(config.treasury.toBase58())}`
  );
  console.log(
    `   Aggregator: ${config.aggregator.equals(PublicKey.default) ? "(not set)" : formatAddress(config.aggregator.toBase58())}`
  );
  console.log(`   Chain Id: ${config.chainId} (expected ${networkConfig.chainId} for ${network})`);
  console.log(`   Max BPS: ${config.maxBps}`);
  console.log(`   Max Order Amount: ${config.maxOrderAmount === 0n ? "uncapped" : config.maxOrderAmount}`);
  console.log(`   Global Escrow Cap: ${config.globalEscrowCap === 0n ? "uncapped" : config.globalEscrowCap}`);
  console.log(`   Paused: ${config.paused}\n`);

  if (config.chainId !== BigInt(networkConfig.chainId)) {
    console.log(
      `   WARNING: on-chain chain_id (${config.chainId}) does not match config.ts's expected value (${networkConfig.chainId}). ` +
        `This is consensus-critical (D3/O2) — every create_order call will fail id verification until this is resolved.\n`
    );
  }

  console.log("Token Support Status:");
  for (const [name, token] of Object.entries(networkConfig.supportedTokens)) {
    const mint = new PublicKey(token.mint);
    const [tokenConfigPda] = findTokenConfigPda(programId, mint);
    const tokenConfigAccount = await connection.getAccountInfo(tokenConfigPda);

    if (!tokenConfigAccount) {
      console.log(`   ${name} (${formatAddress(mint.toBase58())}): not registered`);
      continue;
    }

    const tokenConfig = decodeTokenConfig(tokenConfigAccount.data);
    console.log(
      `   ${name} (${formatAddress(mint.toBase58())}): ` +
        `${tokenConfig.isSupported ? "supported" : "disabled"}, ` +
        `sender->treasury=${tokenConfig.senderToTreasury}bps, ` +
        `provider->treasury=${tokenConfig.providerToTreasury}bps`
    );
  }

  console.log("\nStatus check complete!");
}

checkStatus()
  .then(() => {
    console.log("\nDone!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\nFailed to check status:", error);
    process.exit(1);
  });
