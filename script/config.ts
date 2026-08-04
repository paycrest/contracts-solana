import dotenv from "dotenv";

dotenv.config();

// MAX_BPS = 100_000 (Gateway.sol / GatewaySettingManager.sol parity)
const SENDER_TO_TREASURY_FEE = 0; // 0%
const PROVIDER_TO_TREASURY_FEE = 500; // 0.5%

export interface TokenConfig {
  mint: string;
  senderToTreasury: number;
  providerToTreasury: number;
}

export interface NetworkConfig {
  rpcUrl: string;
  explorerUrl: string;
  /**
   * D3/O2 — the synthetic chain_id baked into the on-chain Config PDA at
   * `initialize` and into every payout order-id keccak preimage. Write-once
   * on-chain (no setter instruction exists); if this drifts from the value
   * actually passed to `initialize`, every create_order call fails PDA
   * verification. Reserved Paycrest band: must never collide with a real
   * EVM chain id or Starknet's SN_MAIN.
   */
  chainId: number;
  supportedTokens: {
    [key: string]: TokenConfig;
  };
  programId?: string; // Will be set after deployment
}

export const NETWORKS: { [network: string]: NetworkConfig } = {
  "mainnet-beta": {
    rpcUrl: process.env.SOLANA_MAINNET_RPC_URL || "https://api.mainnet-beta.solana.com",
    explorerUrl: "https://explorer.solana.com",
    chainId: 900_001,
    supportedTokens: {
      USDC: {
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // Solana USDC
        senderToTreasury: SENDER_TO_TREASURY_FEE,
        providerToTreasury: PROVIDER_TO_TREASURY_FEE,
      },
      USDT: {
        mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // Solana USDT
        senderToTreasury: SENDER_TO_TREASURY_FEE,
        providerToTreasury: PROVIDER_TO_TREASURY_FEE,
      },
    },
  },

  devnet: {
    rpcUrl: process.env.SOLANA_DEVNET_RPC_URL || "https://api.devnet.solana.com",
    explorerUrl: "https://explorer.solana.com",
    chainId: 900_002,
    programId: "BoSMnjq5yfEbGYDAm9QMDwYS1SU2avudcc7JqBKNw77U",
    supportedTokens: {
      // Devnet USDC (Circle's official devnet mint). Replace with a local
      // test mint if you need one that isn't rate-limited.
      USDC: {
        mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        senderToTreasury: SENDER_TO_TREASURY_FEE,
        providerToTreasury: PROVIDER_TO_TREASURY_FEE,
      },
    },
  },
};

/**
 * Get network configuration by network identifier.
 */
export function getNetworkConfig(network: string): NetworkConfig {
  const config = NETWORKS[network];
  if (!config) {
    throw new Error(`Network ${network} not found in configuration`);
  }
  return config;
}
