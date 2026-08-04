import { execSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  assertDeployerEnvironment,
  confirmContinue,
  getAccountExplorerUrl,
  getDeployerKeypair,
  getProgramId,
} from "./utils";
import { getNetworkConfig } from "./config";
import dotenv from "dotenv";

dotenv.config();

const network = process.argv[2] || "devnet";

assertDeployerEnvironment();

const SO_PATH = path.join(__dirname, "../target/deploy/paycrest_gateway.so");

/**
 * D11 — the program's upgrade authority is a single keypair (KMS/HSM in
 * production), separate from Config.owner. This script assumes the
 * deployer keypair in .env currently holds that authority; the runtime
 * will reject the upgrade otherwise. Migrating authority to a multisig
 * later (`solana program set-upgrade-authority`) does not change how this
 * script is invoked — only who can successfully run it.
 */
async function upgradeGateway() {
  console.log("\n=== Upgrading Paycrest Gateway on Solana ===");
  console.log(`Network: ${network}\n`);

  const networkConfig = getNetworkConfig(network);
  const authority = getDeployerKeypair();
  const programId = getProgramId(network);

  if (!fs.existsSync(SO_PATH)) {
    throw new Error(
      `Program binary not found at ${SO_PATH}. Run 'cargo-build-sbf --manifest-path program/Cargo.toml' first.`
    );
  }

  await confirmContinue({
    Network: network,
    "Program Id": programId.toBase58(),
    "Upgrade Authority": authority.publicKey.toBase58(),
    Warning: "This replaces the program's logic in place. Account data layouts are NOT migrated automatically.",
  });

  console.log("Upgrading program binary via `solana program deploy`...");
  const tempKeypairPath = path.join(os.tmpdir(), `paycrest-upgrade-authority-${Date.now()}.json`);
  fs.writeFileSync(tempKeypairPath, JSON.stringify(Array.from(authority.secretKey)), { mode: 0o600 });
  try {
    const upgradeCommand = [
      "solana program deploy",
      `"${SO_PATH}"`,
      `--program-id "${programId.toBase58()}"`,
      `--url "${networkConfig.rpcUrl}"`,
      `--keypair "${tempKeypairPath}"`,
      "--upgrade-authority",
      `"${tempKeypairPath}"`,
    ].join(" ");
    execSync(upgradeCommand, { stdio: "inherit" });
  } finally {
    fs.rmSync(tempKeypairPath, { force: true });
  }

  console.log(`\n=== Program upgraded: ${programId.toBase58()} ===`);
  console.log(`   Explorer: ${getAccountExplorerUrl(network, programId.toBase58())}`);
  console.log("\nRun 'npm run check-status' to verify Config/TokenConfig state is unaffected.");
}

upgradeGateway()
  .then(() => {
    console.log("\nDone!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n[ERROR] Upgrade failed:", error);
    process.exit(1);
  });
