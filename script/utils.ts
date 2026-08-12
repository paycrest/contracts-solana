import readline from "readline";
import dotenv from "dotenv";
import * as fs from "fs";
import * as path from "path";
import bs58 from "bs58";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { getNetworkConfig } from "./config";

dotenv.config();

// ---------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------

export const assertDeployerEnvironment = () => {
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    console.error("Please set DEPLOYER_PRIVATE_KEY in a .env file (base58 secret key)");
    process.exit(1);
  }
};

export const assertEnvironment = () => {
  assertDeployerEnvironment();
  if (!process.env.TREASURY_ADDRESS) {
    console.error("Please set TREASURY_ADDRESS in a .env file");
    process.exit(1);
  }
  if (!process.env.AGGREGATOR_ADDRESS) {
    console.error("Please set AGGREGATOR_ADDRESS in a .env file");
    process.exit(1);
  }
};

export function getDeployerKeypair(): Keypair {
  assertDeployerEnvironment();
  const secret = process.env.DEPLOYER_PRIVATE_KEY!.trim();
  // Accept either a base58 string or a JSON byte array (both are common
  // `solana-keygen` / wallet export formats).
  if (secret.startsWith("[")) {
    return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(secret)));
  }
  return Keypair.fromSecretKey(bs58.decode(secret));
}

// ---------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------

export async function waitForInput(query: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) =>
    rl.question(query, (ans) => {
      rl.close();
      resolve(ans);
    })
  );
}

export async function confirmContinue(params: Record<string, unknown>) {
  console.log("\nPARAMETERS");
  console.table(params);
  const response = await waitForInput("\nDo you want to continue? (y/N): ");
  if (response.toLowerCase() !== "y") {
    throw new Error("Aborting script: user chose to exit");
  }
  console.log("\n");
}

// ---------------------------------------------------------------------
// Connection / program id
// ---------------------------------------------------------------------

export function getConnection(network: string): Connection {
  const config = getNetworkConfig(network);
  return new Connection(config.rpcUrl, "confirmed");
}

export function getProgramId(network: string): PublicKey {
  const fromEnv = process.env.PROGRAM_ID;
  const fromConfig = getNetworkConfig(network).programId;
  const id = fromEnv || fromConfig;
  if (!id) {
    throw new Error(
      `No program id for network ${network}. Set PROGRAM_ID in .env or run 'npm run deploy' first.`
    );
  }
  return new PublicKey(id);
}

/**
 * Update config.ts with the deployed program id, mirroring the Starknet
 * script's updateConfigFile — keeps a redeploy from silently going stale.
 */
export async function updateConfigFile(network: string, programId: string): Promise<void> {
  const configFilePath = path.join(__dirname, "config.ts");
  const original = await fs.promises.readFile(configFilePath, "utf-8");
  let content = original;

  // Network keys are only quoted in config.ts when they aren't valid JS
  // identifiers (e.g. "mainnet-beta" needs quotes, `devnet` doesn't) — the
  // key itself may appear either way, so match both.
  const keyPattern = `"?${network}"?`;
  const programIdLine = `programId: "${programId}"`;
  const existing = new RegExp(`(${keyPattern}:\\s*{(?:(?!\\n  },)[\\s\\S])*?)programId:\\s*"[^"]*"`, "m");

  if (existing.test(content)) {
    content = content.replace(existing, `$1${programIdLine}`);
  } else {
    // Insert as the first property right after the network's opening
    // brace, rather than hunting for "the right" closing brace among
    // `supportedTokens`'s own nested objects — a non-greedy match for the
    // latter previously landed on the first `}` it found, which was
    // `USDC: { ... }`'s, not `supportedTokens`'s, and silently produced
    // invalid TypeScript (programId nested inside supportedTokens).
    const openBrace = new RegExp(`(${keyPattern}:\\s*{)`, "m");
    content = content.replace(openBrace, `$1\n    ${programIdLine},`);
  }

  // `String.replace` silently no-ops and returns the input unchanged if
  // the pattern never matched — don't report success in that case, the
  // way this function used to (it printed "Updated" for devnet while
  // writing back the exact same content it read).
  if (content === original) {
    throw new Error(
      `updateConfigFile: no match for network "${network}" in config.ts — file was not modified. ` +
        `Add "programId: \\"${programId}\\"" to the ${network} block manually.`
    );
  }
  if (!content.includes(programIdLine)) {
    throw new Error(`updateConfigFile: replacement ran but "${programIdLine}" is not present in the result.`);
  }

  await fs.promises.writeFile(configFilePath, content, "utf-8");
  console.log(`Updated config.ts with program id: ${programId}`);
}

// ---------------------------------------------------------------------
// PDAs — seeds must match program/src/constants.rs exactly
// ---------------------------------------------------------------------

export function findConfigPda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("config")], programId);
}

export function findTokenConfigPda(programId: PublicKey, mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("token"), mint.toBuffer()], programId);
}

export function findVaultAuthorityPda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("vault_authority")], programId);
}

export function findOrderPda(programId: PublicKey, orderId: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("order"), orderId], programId);
}

/** Legacy SPL Token program — pinned in program (D9). */
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

/** Anchor-compatible event discriminator from program/src/constants.rs */
export const EVT_ORDER_CREATED = Buffer.from([0xe0, 0x01, 0xe5, 0x3f, 0xfe, 0x3c, 0xbe, 0x9f]);

/** Left-pad u64 into 32-byte big-endian word (Solidity uint256). */
export function u64AsUint256BE(value: bigint | number): Buffer {
  const buf = Buffer.alloc(32);
  buf.writeBigUInt64BE(BigInt(value), 24);
  return buf;
}

/** keccak256(depositor || uint256(nonce) || uint256(chain_id)) — D3 */
export function orderIdHash(depositor: PublicKey, nonce: bigint, chainId: bigint): Buffer {
  const { keccak_256 } = require("js-sha3") as typeof import("js-sha3");
  const preimage = Buffer.concat([
    depositor.toBuffer(),
    u64AsUint256BE(nonce),
    u64AsUint256BE(chainId),
  ]);
  return Buffer.from(keccak_256.array(preimage));
}

/** Probe PDAs for the first unoccupied nonce (N1). */
export async function findNextFreeNonce(
  connection: Connection,
  programId: PublicKey,
  depositor: PublicKey,
  chainId: bigint,
  maxProbe = 64
): Promise<{ nonce: bigint; orderPda: PublicKey; orderBump: number; orderId: Buffer }> {
  for (let n = 1n; n <= BigInt(maxProbe); n++) {
    const orderId = orderIdHash(depositor, n, chainId);
    const [orderPda, bump] = findOrderPda(programId, orderId);
    const info = await connection.getAccountInfo(orderPda);
    if (info === null) {
      return { nonce: n, orderPda, orderBump: bump, orderId };
    }
  }
  throw new Error(`no free nonce in 1..${maxProbe} for depositor ${depositor.toBase58()}`);
}


// ---------------------------------------------------------------------
// Instruction encoders — opcode + field layout must match
// program/src/lib.rs's Opcode enum and each instructions/admin.rs handler
// byte-for-byte. There is no IDL/Anchor client generating this; it is
// hand-written and independently verified against the Rust source (D13).
// ---------------------------------------------------------------------

enum Opcode {
  Initialize = 0,
  SetTokenSupport = 1,
  SetTokenFeeSettings = 2,
  UpdateProtocolAddress = 3,
  TransferOwnership = 4,
  AcceptOwnership = 5,
  Pause = 6,
  Unpause = 7,
  SetCaps = 8,
  CreateOrder = 9,
  SettleOut = 10,
  SettleIn = 11,
  Refund = 12,
}

function u64le(value: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(value));
  return buf;
}

/** Initialize: opcode(1) bump(1) chain_id(8 LE) = 10 bytes. */
export function encodeInitialize(bump: number, chainId: number): Buffer {
  return Buffer.concat([Buffer.from([Opcode.Initialize, bump]), u64le(chainId)]);
}

/** SetTokenSupport: opcode(1) bump(1) status(1: 1=supported, 2=unsupported) = 3 bytes. */
export function encodeSetTokenSupport(bump: number, isSupported: boolean): Buffer {
  return Buffer.from([Opcode.SetTokenSupport, bump, isSupported ? 1 : 2]);
}

/** SetTokenFeeSettings: opcode(1) sender_to_treasury(8 LE) provider_to_treasury(8 LE) = 17 bytes. */
export function encodeSetTokenFeeSettings(senderToTreasury: number, providerToTreasury: number): Buffer {
  return Buffer.concat([
    Buffer.from([Opcode.SetTokenFeeSettings]),
    u64le(senderToTreasury),
    u64le(providerToTreasury),
  ]);
}

/** UpdateProtocolAddress: opcode(1) what(1: 0=treasury,1=aggregator) new_address(32) = 34 bytes. */
export function encodeUpdateProtocolAddress(what: "treasury" | "aggregator", newAddress: PublicKey): Buffer {
  return Buffer.concat([
    Buffer.from([Opcode.UpdateProtocolAddress, what === "treasury" ? 0 : 1]),
    newAddress.toBuffer(),
  ]);
}

/** TransferOwnership: opcode(1) new_owner(32) = 33 bytes. */
export function encodeTransferOwnership(newOwner: PublicKey): Buffer {
  return Buffer.concat([Buffer.from([Opcode.TransferOwnership]), newOwner.toBuffer()]);
}

/** AcceptOwnership: opcode(1) = 1 byte, no further data. */
export function encodeAcceptOwnership(): Buffer {
  return Buffer.from([Opcode.AcceptOwnership]);
}

export function encodePause(): Buffer {
  return Buffer.from([Opcode.Pause]);
}

export function encodeUnpause(): Buffer {
  return Buffer.from([Opcode.Unpause]);
}

/** SetCaps: opcode(1) max_order_amount(8 LE) global_escrow_cap(8 LE) = 17 bytes. 0 = uncapped (D15). */
export function encodeSetCaps(maxOrderAmount: bigint, globalEscrowCap: bigint): Buffer {
  return Buffer.concat([Buffer.from([Opcode.SetCaps]), u64le(maxOrderAmount), u64le(globalEscrowCap)]);
}

/** CreateOrder fixed prefix + trailing message blob — see create_order.rs */
export function encodeCreateOrder(params: {
  orderBump: number;
  vaultBump: number;
  nonce: bigint;
  amount: bigint;
  rate: bigint;
  senderFee: bigint;
  senderFeeRecipient: PublicKey;
  refundAddress: PublicKey;
  messageHash: Buffer;
}): Buffer {
  return Buffer.concat([
    Buffer.from([Opcode.CreateOrder, params.orderBump, params.vaultBump]),
    u64le(params.nonce),
    u64le(params.amount),
    u64le(params.rate),
    u64le(params.senderFee),
    params.senderFeeRecipient.toBuffer(),
    params.refundAddress.toBuffer(),
    params.messageHash,
  ]);
}


// ---------------------------------------------------------------------
// State decoders — offsets must match program/src/state/{config,token_config}.rs
// exactly. Independent of the Rust (de)serializers, same reasoning as the
// encoders above.
// ---------------------------------------------------------------------

export const CONFIG_LEN = 235;
export const TOKEN_CONFIG_LEN = 91;
export const TAG_CONFIG = Buffer.from([0x9b, 0x0c, 0xaa, 0xe0, 0x1e, 0xfa, 0xcc, 0x82]);
export const TAG_TOKEN_CONFIG = Buffer.from([0x5c, 0x49, 0xff, 0x2b, 0x6b, 0x33, 0x75, 0x65]);

export interface DecodedConfig {
  version: number;
  bump: number;
  paused: boolean;
  owner: PublicKey;
  pendingOwner: PublicKey;
  aggregator: PublicKey;
  treasury: PublicKey;
  chainId: bigint;
  maxBps: bigint;
  maxOrderAmount: bigint;
  globalEscrowCap: bigint;
}

export function decodeConfig(data: Buffer): DecodedConfig {
  if (data.length !== CONFIG_LEN) {
    throw new Error(`Config account has unexpected length ${data.length} (want ${CONFIG_LEN})`);
  }
  if (!data.subarray(0, 8).equals(TAG_CONFIG)) {
    throw new Error("Config account discriminator mismatch");
  }
  return {
    version: data[8],
    bump: data[9],
    paused: data[10] !== 0,
    owner: new PublicKey(data.subarray(11, 43)),
    pendingOwner: new PublicKey(data.subarray(43, 75)),
    aggregator: new PublicKey(data.subarray(75, 107)),
    treasury: new PublicKey(data.subarray(107, 139)),
    chainId: data.readBigUInt64LE(139),
    maxBps: data.readBigUInt64LE(147),
    maxOrderAmount: data.readBigUInt64LE(155),
    globalEscrowCap: data.readBigUInt64LE(163),
  };
}

export interface DecodedTokenConfig {
  version: number;
  bump: number;
  isSupported: boolean;
  mint: PublicKey;
  senderToTreasury: bigint;
  providerToTreasury: bigint;
}

export function decodeTokenConfig(data: Buffer): DecodedTokenConfig {
  if (data.length !== TOKEN_CONFIG_LEN) {
    throw new Error(`TokenConfig account has unexpected length ${data.length} (want ${TOKEN_CONFIG_LEN})`);
  }
  if (!data.subarray(0, 8).equals(TAG_TOKEN_CONFIG)) {
    throw new Error("TokenConfig account discriminator mismatch");
  }
  return {
    version: data[8],
    bump: data[9],
    isSupported: data[10] !== 0,
    mint: new PublicKey(data.subarray(11, 43)),
    senderToTreasury: data.readBigUInt64LE(43),
    providerToTreasury: data.readBigUInt64LE(51),
  };
}

// ---------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------

export async function sendAndConfirm(
  connection: Connection,
  network: string,
  instruction: TransactionInstruction,
  signer: Keypair
): Promise<string> {
  const tx = new Transaction().add(instruction);
  const signature = await sendAndConfirmTransaction(connection, tx, [signer], {
    commitment: "confirmed",
  });
  console.log(`   Transaction: ${signature}`);
  console.log(`   Explorer: ${getExplorerUrl(network, signature)}`);
  return signature;
}

export function getExplorerUrl(network: string, signature: string): string {
  const config = getNetworkConfig(network);
  const cluster = network === "mainnet-beta" ? "" : `?cluster=${network}`;
  return `${config.explorerUrl}/tx/${signature}${cluster}`;
}

export function getAccountExplorerUrl(network: string, address: string): string {
  const config = getNetworkConfig(network);
  const cluster = network === "mainnet-beta" ? "" : `?cluster=${network}`;
  return `${config.explorerUrl}/address/${address}${cluster}`;
}

export function formatAddress(address: string): string {
  if (address.length <= 10) return address;
  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
