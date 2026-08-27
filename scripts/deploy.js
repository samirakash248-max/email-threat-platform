const hre = require("hardhat");

async function main() {
  console.log("============================================================");
  console.log("🚀 Deploying ThreatSentinel Smart Contracts...");
  console.log("📡 Target Network:", hre.network.name);
  console.log("============================================================");

  const [deployer] = await hre.ethers.getSigners();
  console.log("👤 Deployer Account:", deployer.address);
  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("💰 Account Balance:", balance.toString(), "wei");
  console.log("------------------------------------------------------------");

  // 1. Deploy EvidenceRegistry
  console.log("📦 [1/2] Deploying EvidenceRegistry...");
  const EvidenceRegistry = await hre.ethers.getContractFactory("EvidenceRegistry");
  const evidenceRegistry = await EvidenceRegistry.deploy();
  await evidenceRegistry.waitForDeployment();
  const evidenceRegistryAddr = await evidenceRegistry.getAddress();
  console.log("✅ EvidenceRegistry deployed at:", evidenceRegistryAddr);

  // 2. Deploy ThreatIntelRegistry
  console.log("📦 [2/2] Deploying ThreatIntelRegistry...");
  const ThreatIntelRegistry = await hre.ethers.getContractFactory("ThreatIntelRegistry");
  const threatIntelRegistry = await ThreatIntelRegistry.deploy();
  await threatIntelRegistry.waitForDeployment();
  const threatIntelRegistryAddr = await threatIntelRegistry.getAddress();
  console.log("✅ ThreatIntelRegistry deployed at:", threatIntelRegistryAddr);

  console.log("============================================================");
  console.log("🎉 All Smart Contracts Deployed Successfully!");
  console.log("============================================================");
  console.log("Copy these contract addresses into your backend .env file:\n");
  console.log(`BLOCKCHAIN_CONTRACT_ADDRESS="${evidenceRegistryAddr}"`);
  console.log(`BLOCKCHAIN_INTEL_CONTRACT_ADDRESS="${threatIntelRegistryAddr}"`);
  console.log("============================================================");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("❌ Deployment failed:", error);
    process.exit(1);
  });
