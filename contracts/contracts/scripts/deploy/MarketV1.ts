import { ethers, upgrades, run } from 'hardhat';
import { Contract } from 'ethers';
import * as fs from 'fs';

import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { upgrade as upgradeUtil } from './Upgrade';

import * as configI from './config.json';
const config = configI as any;

export async function deploy(): Promise<Contract> {
  const MarketV1 = await ethers.getContractFactory('MarketV1');

  let chainId = (await ethers.provider.getNetwork()).chainId.toString();
  console.log("Chain Id:", chainId);

  const chainConfig = config[chainId];

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if (addresses[chainId] === undefined) {
    addresses[chainId] = {};
  }

  if (addresses[chainId]['MarketV1'] !== undefined) {
    console.log("Existing deployment:", addresses[chainId]['MarketV1']);
    return MarketV1.attach(addresses[chainId]['MarketV1']);
  }

  let paymentToken = addresses[chainId][chainConfig.enclaves.paymentToken];
  if (paymentToken === undefined) {
    if (chainConfig.enclaves.paymentToken.startsWith("0x")) {
      paymentToken = chainConfig.enclaves.paymentToken;
    } else {
      throw new Error("Payment token unavailable");
    }
  }

  let lockSelectors = chainConfig.enclaves.lockWaitTimes.map((a: any) => a.selector);
  let lockWaitTimes = chainConfig.enclaves.lockWaitTimes.map((a: any) => a.time);

  if (lockSelectors?.length != lockWaitTimes?.length) {
    throw new Error("lockSelectors and lockWaitTimes not matching lengths");
  }

  let admin = chainConfig.admin;

  let marketV1 = await upgrades.deployProxy(MarketV1, [admin, paymentToken, lockSelectors, lockWaitTimes], { kind: "uups" });

  console.log("Deployed addr:", await marketV1.getAddress());

  addresses[chainId]['MarketV1'] = await marketV1.getAddress();

  fs.writeFileSync('address.json', JSON.stringify(addresses, null, 2), 'utf8');

  return marketV1;
}

export async function upgrade() {
  await upgradeUtil('MarketV1', 'MarketV1', []);
}

export async function verify() {
  let chainId = (await ethers.provider.getNetwork()).chainId.toString();
  console.log("Chain Id:", chainId);

  var addresses: { [key: string]: { [key: string]: string } } = {};
  if (fs.existsSync('address.json')) {
    addresses = JSON.parse(fs.readFileSync('address.json', 'utf8'));
  }

  if (addresses[chainId] === undefined || addresses[chainId]['MarketV1'] === undefined) {
    throw new Error("MarketV1 not deployed");
  }

  const implAddress = await upgrades.erc1967.getImplementationAddress(addresses[chainId]['MarketV1']);

  await run("verify:verify", {
    address: implAddress,
    constructorArguments: []
  });

  console.log("MarketV1 verified");
}

yargs(hideBin(process.argv))
  .command({
    command: 'deploy',
    describe: 'Deploy the contract',
    handler: (_argv) => deploy().then(),
  })
  .command({
    command: 'upgrade',
    describe: 'Upgrade the contract',
    handler: (_argv) => upgrade().then(),
  })
  .command({
    command: 'verify',
    describe: 'Verify the contract',
    handler: (_argv) => verify().then(),
  })
  .demandCommand(1, 'expected a command from deploy, upgrade or verify')
  .strict()
  .help()
  .argv;
