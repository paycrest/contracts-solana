import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/** Path to the deployable program artifact produced by `cargo-build-sbf`. */
export const PROGRAM_SO_PATH = path.join(__dirname, "../target/deploy/paycrest_gateway.so");

const PROGRAM_CARGO_MANIFEST = path.join(__dirname, "../program/Cargo.toml");

/** Rebuild `target/deploy/paycrest_gateway.so` from current sources. */
export function buildProgramSo(): void {
  console.log("Building program via cargo-build-sbf...");
  execSync(`cargo-build-sbf --manifest-path "${PROGRAM_CARGO_MANIFEST}"`, {
    stdio: "inherit",
    cwd: path.join(__dirname, ".."),
  });
  if (!fs.existsSync(PROGRAM_SO_PATH)) {
    throw new Error(`Build finished but artifact missing at ${PROGRAM_SO_PATH}`);
  }
}

/** Content hash of a local `.so` (same algorithm as `solana-verify get-program-hash`). */
export function getExecutableHash(soPath: string = PROGRAM_SO_PATH): string {
  if (!fs.existsSync(soPath)) {
    throw new Error(`Program binary not found at ${soPath}`);
  }
  try {
    return execSync(`solana-verify get-executable-hash "${soPath}"`, { encoding: "utf8" }).trim();
  } catch {
    throw new Error(
      "solana-verify is required to compute program hashes. Install it and ensure it is on PATH."
    );
  }
}

/** On-chain program content hash at `programId`. */
export function getOnChainProgramHash(rpcUrl: string, programId: string): string {
  return execSync(`solana-verify get-program-hash --url "${rpcUrl}" ${programId}`, {
    encoding: "utf8",
  }).trim();
}

/** Assert on-chain bytecode matches the local artifact after deploy/upgrade. */
export function assertOnChainProgramHash(rpcUrl: string, programId: string, expectedHash: string): void {
  const onChain = getOnChainProgramHash(rpcUrl, programId);
  if (onChain !== expectedHash) {
    throw new Error(
      `On-chain program hash mismatch after deploy.\n  expected: ${expectedHash}\n  on-chain: ${onChain}`
    );
  }
  console.log(`   Verified on-chain hash: ${onChain}`);
}
