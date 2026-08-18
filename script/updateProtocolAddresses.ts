import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import {
  assertEnvironment,
  confirmContinue,
  encodeUpdateProtocolAddress,
  findConfigPda,
  getConnection,
  getDeployerKeypair,
  getProgramId,
  sendAndConfirm,
} from "./utils";
import dotenv from "dotenv";

dotenv.config();

const network = process.argv[2] || "devnet";

assertEnvironment();

async function updateProtocolAddresses() {
  console.log("\n=== Updating Paycrest Gateway Protocol Addresses ===");
  console.log(`Network: ${network}\n`);

  const programId = getProgramId(network);
  const owner = getDeployerKeypair();
  const [configPda] = findConfigPda(programId);
  const treasury = new PublicKey(process.env.TREASURY_ADDRESS!);
  const aggregator = new PublicKey(process.env.AGGREGATOR_ADDRESS!);

  await confirmContinue({
    Network: network,
    "Program Id": programId.toBase58(),
    "Config PDA": configPda.toBase58(),
    Owner: owner.publicKey.toBase58(),
    Treasury: treasury.toBase58(),
    Aggregator: aggregator.toBase58(),
  });

  const connection = getConnection(network);

  console.log("[1/2] Setting treasury address...");
  const treasuryIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: owner.publicKey, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
    ],
    data: encodeUpdateProtocolAddress("treasury", treasury),
  });
  await sendAndConfirm(connection, network, treasuryIx, owner);

  console.log("\n[2/2] Setting aggregator address...");
  const aggregatorIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: owner.publicKey, isSigner: true, isWritable: false },
      { pubkey: configPda, isSigner: false, isWritable: true },
    ],
    data: encodeUpdateProtocolAddress("aggregator", aggregator),
  });
  await sendAndConfirm(connection, network, aggregatorIx, owner);

  console.log("\n=== Protocol addresses updated! ===");
}

updateProtocolAddresses()
  .then(() => {
    console.log("\nDone!");
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
