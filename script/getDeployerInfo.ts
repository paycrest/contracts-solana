import { getConnection, getDeployerKeypair } from "./utils";
import dotenv from "dotenv";

dotenv.config();

const network = process.argv[2] || "devnet";

async function getDeployerInfo() {
  const deployer = getDeployerKeypair();
  const connection = getConnection(network);
  const balanceLamports = await connection.getBalance(deployer.publicKey);

  console.log("\nDeployer Info:");
  console.log(`   Network: ${network}`);
  console.log(`   Address: ${deployer.publicKey.toBase58()}`);
  console.log(`   Balance: ${(balanceLamports / 1_000_000_000).toFixed(6)} SOL`);

  if (balanceLamports === 0) {
    console.log(
      `\n   Zero balance. On devnet, fund with: solana airdrop 2 ${deployer.publicKey.toBase58()} --url ${
        connection.rpcEndpoint
      }`
    );
  }
}

getDeployerInfo()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
