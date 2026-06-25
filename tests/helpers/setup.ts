import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { SolanaGateway } from "../../target/types/solana_gateway";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  Connection,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint, createAccount, mintTo } from "@solana/spl-token";

// Deterministic keypairs for test reproducibility
function keypairFromSeed(seed: string): Keypair {
  const hash = Buffer.alloc(32);
  Buffer.from(seed).copy(hash);
  return Keypair.fromSeed(hash);
}

export const DEPLOYER_KP = keypairFromSeed("paycrest-deployer-YamaVRSB27o");
export const AGGREGATOR_KP = keypairFromSeed("paycrest-test-aggregator-key!");
export const TREASURY_KP = keypairFromSeed("paycrest-test-treasury-keypair");

export interface SetupResult {
  program: Program<SolanaGateway>;
  connection: Connection;
  owner: anchor.Wallet;
  mint: PublicKey;
  configPda: PublicKey;
  vaultAuthorityPda: PublicKey;
  tokenConfigPda: PublicKey;
  vaultTokenAccount: PublicKey;
  treasuryTokenAccount: PublicKey;
  senderStatePda: (sender: PublicKey) => PublicKey;
  orderPda: (sender: PublicKey, nonce: number) => PublicKey;
}

export async function setupProtocol(): Promise<SetupResult> {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SolanaGateway as Program<SolanaGateway>;
  const connection = provider.connection;
  const owner = provider.wallet as anchor.Wallet;

  // PDAs
  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    program.programId
  );
  const [vaultAuthorityPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault_authority")],
    program.programId
  );

  // Airdrop to aggregator
  const aggBal = await connection.getBalance(AGGREGATOR_KP.publicKey);
  if (aggBal < LAMPORTS_PER_SOL) {
    const sig = await connection.requestAirdrop(AGGREGATOR_KP.publicKey, 5 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig);
  }

  // Initialize (idempotent)
  const configAccount = await connection.getAccountInfo(configPda);
  if (!configAccount) {
    await program.methods
      .initialize()
      .accounts({
        owner: owner.publicKey,
        treasury: TREASURY_KP.publicKey,
        aggregator: AGGREGATOR_KP.publicKey,
      })
      .rpc();
  } else {
    // Ensure protocol is not paused (state may carry over from other test files)
    try {
      const config = await program.account.config.fetch(configPda);
      if (config.paused) {
        await program.methods
          .unpause()
          .accounts({
            owner: owner.publicKey,
            config: configPda,
          })
          .rpc();
      }
    } catch {}
  }

  // Create mint (SPL Token classic — NOT Token-2022)
  const mint = await createMint(connection, owner.payer, owner.publicKey, null, 6);

  const [tokenConfigPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("token"), mint.toBuffer()],
    program.programId
  );
  const [vaultTokenAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from("vault"), mint.toBuffer()],
    program.programId
  );

  // Support token + fee settings
  await program.methods
    .setTokenSupport(1)
    .accounts({
      mint,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .rpc();

  await program.methods
    .setTokenFeeSettings(
      new anchor.BN(60_000),  // sender_to_provider (60%)
      new anchor.BN(10_000),  // provider_to_aggregator (10%)
      new anchor.BN(5_000),   // sender_to_aggregator (5%)
      new anchor.BN(500)      // provider_to_aggregator_fx (0.5%)
    )
    .accounts({
      mint,
      
    })
    .rpc();

  // Treasury token account
  const treasuryTokenAccount = await createAccount(
    connection, owner.payer, mint, TREASURY_KP.publicKey
  );

  // Helper functions
  const senderStatePda = (sender: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("nonce"), sender.toBuffer()],
      program.programId
    )[0];

  const orderPda = (sender: PublicKey, nonce: number) => {
    const nonceBuf = Buffer.alloc(8);
    nonceBuf.writeBigUInt64LE(BigInt(nonce));
    return PublicKey.findProgramAddressSync(
      [Buffer.from("order"), sender.toBuffer(), nonceBuf],
      program.programId
    )[0];
  };

  return {
    program, connection, owner, mint,
    configPda, vaultAuthorityPda, tokenConfigPda,
    vaultTokenAccount, treasuryTokenAccount,
    senderStatePda, orderPda,
  };
}

export async function fundWallet(
  connection: Connection,
  payer: Keypair,
  mint: PublicKey,
  owner: PublicKey,
  amount: number
): Promise<PublicKey> {
  const tokenAccount = await createAccount(connection, payer, mint, owner);
  await mintTo(connection, payer, mint, tokenAccount, payer, amount);
  return tokenAccount;
}
