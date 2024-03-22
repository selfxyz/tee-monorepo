import { expect } from "chai";
import { Contract, Signer, toBigInt } from "ethers";
import { ethers, upgrades } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

import { MarketV1 } from "../typechain-types";
import { takeSnapshotBeforeAndAfterEveryTest } from "../utils/testSuite";
import { testERC165 } from "./helpers/erc165";
import { testAdminRole } from "./helpers/rbac";


const RATE_LOCK = ethers.id("RATE_LOCK");
const SELECTORS = [RATE_LOCK];
const WAIT_TIMES: number[] = [600];

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("deploys with initialization disabled", async function() {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await MarketV1.deploy();

		await expect(
			marketv1.initialize(addrs[0], addrs[11], SELECTORS, WAIT_TIMES),
		).to.be.revertedWithCustomError(marketv1, "InvalidInitialization");
	});

	it("deploys as proxy and initializes", async function() {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		);

		await Promise.all(
			SELECTORS.map(async (s, idx) => {
				expect(await marketv1.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
			}),
		);
		expect(
			await marketv1.hasRole(await marketv1.DEFAULT_ADMIN_ROLE(), addrs[0]),
		).to.be.true;
		expect(await marketv1.token()).to.equal(addrs[11]);
	});

	it("does not initialize with mismatched lengths", async function() {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		await expect(
			upgrades.deployProxy(
				MarketV1,
				[addrs[0], addrs[11], SELECTORS, [...WAIT_TIMES, 0]],
				{ kind: "uups" },
			),
		).to.be.revertedWithCustomError(MarketV1, "MarketV1InitLengthMismatch");
	});

	it("upgrades", async function() {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		);
		await upgrades.upgradeProxy(await marketv1.getAddress(), MarketV1, { kind: "uups" });

		await Promise.all(
			SELECTORS.map(async (s, idx) => {
				expect(await marketv1.lockWaitTime(s)).to.equal(WAIT_TIMES[idx]);
			}),
		);
		expect(
			await marketv1.hasRole(await marketv1.DEFAULT_ADMIN_ROLE(), addrs[0]),
		).to.be.true;
		expect(await marketv1.token()).to.equal(addrs[11]);
	});

	it("does not upgrade without admin", async function() {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		);

		await expect(
			upgrades.upgradeProxy(await marketv1.getAddress(), MarketV1.connect(signers[1]), {
				kind: "uups",
			}),
		).to.be.revertedWithCustomError(marketv1, "AccessControlUnauthorizedAccount");
	});
});

testERC165(
	"MarketV1",
	async function(_signers: Signer[], addrs: string[]) {
		const MarketV1 = await ethers.getContractFactory("MarketV1");
		const marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		);
		return marketv1;
	},
	{
		IAccessControl: [
			"hasRole(bytes32,address)",
			"getRoleAdmin(bytes32)",
			"grantRole(bytes32,address)",
			"revokeRole(bytes32,address)",
			"renounceRole(bytes32,address)",
		],
		IAccessControlEnumerable: [
			"getRoleMember(bytes32,uint256)",
			"getRoleMemberCount(bytes32)",
		],
	},
);

testAdminRole("MarketV1", async function(_signers: Signer[], addrs: string[]) {
	const MarketV1 = await ethers.getContractFactory("MarketV1");
	const marketv1 = await upgrades.deployProxy(
		MarketV1,
		[addrs[0], addrs[11], SELECTORS, WAIT_TIMES],
		{ kind: "uups" },
	);
	return marketv1;
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can register as provider", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");

		expect(await marketv1.providers(addrs[1])).to.equal("https://example.com/");
	});

	it("cannot register as provider with empty cp", async () => {
		await expect(
			marketv1.connect(signers[1]).providerAdd(""),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderInvalidCp");
	});

	it("cannot register as provider if already registered", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");

		await expect(
			marketv1.connect(signers[1]).providerAdd("https://example.com/"),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderAlreadyExists");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can unregister as provider", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");
		await marketv1.connect(signers[1]).providerRemove();

		expect(await marketv1.providers(addrs[1])).to.equal("");
	});

	it("cannot unregister as provider if never registered", async () => {
		await expect(
			marketv1.connect(signers[1]).providerRemove(),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderNotFound");
	});

	it("cannot register as provider if already unregistered", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");
		await marketv1.connect(signers[1]).providerRemove();

		await expect(
			marketv1.connect(signers[1]).providerRemove(),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderNotFound");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can update cp", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");
		await marketv1
			.connect(signers[1])
			.providerUpdateWithCp("https://example.com/new");

		expect(await marketv1.providers(addrs[1])).to.equal(
			"https://example.com/new",
		);
	});

	it("cannot update to empty cp", async () => {
		await marketv1.connect(signers[1]).providerAdd("https://example.com/");
		await expect(
			marketv1.connect(signers[1]).providerUpdateWithCp(""),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderInvalidCp");
	});

	it("cannot update if never registered", async () => {
		await expect(
			marketv1
				.connect(signers[1])
				.providerUpdateWithCp("https://example.com/new"),
		).to.be.revertedWithCustomError(marketv1, "MarketV1ProviderNotFound");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can open job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 50);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		const jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);
	});

	it("cannot open job without enough approved", async () => {
		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 49);
		await expect(
			marketv1.connect(signers[1]).jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50),
		).to.be.revertedWithCustomError(pond, "ERC20InsufficientAllowance");
	});

	it("cannot open job without enough balance", async () => {
		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 5000);
		await expect(
			marketv1.connect(signers[1]).jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 5000),
		).to.be.revertedWithCustomError(pond, "ERC20InsufficientBalance");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can settle job with enough balance", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 50);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		ts = jobInfo.lastSettled;

		await time.increaseTo(ts + 5n);
		await marketv1.jobSettle(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		let amount = 5n * (jobInfo.lastSettled - ts);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.be.equal(50n - amount);
		expect(jobInfo.lastSettled).to.be.within(ts + 5n, ts + 6n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(addrs[2])).to.equal(amount);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50n - amount);
	});

	it("can settle job without enough balance", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 50);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		ts = jobInfo.lastSettled;

		await time.increaseTo(ts + 11n);
		await marketv1.jobSettle(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(0);
		expect(jobInfo.lastSettled).to.be.within(ts + 11n, ts + 12n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(addrs[2])).to.equal(50);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(0);
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can deposit to job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 75);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		await marketv1
			.connect(signers[1])
			.jobDeposit(ethers.ZeroHash, 25);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(75);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(925);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(75);
	});

	it("cannot deposit to job without enough approved", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 74);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		await expect(marketv1
			.connect(signers[1])
			.jobDeposit(ethers.ZeroHash, 25)).to.be.revertedWithCustomError(pond, "ERC20InsufficientAllowance");
	});

	it("cannot deposit to job without enough balance", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 5000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		await expect(marketv1
			.connect(signers[1])
			.jobDeposit(ethers.ZeroHash, 951)).to.be.revertedWithCustomError(pond, "ERC20InsufficientBalance");
	});

	it("cannot deposit to never registered job", async () => {
		await expect(marketv1
			.connect(signers[1])
			.jobDeposit(ethers.zeroPadValue("0x01", 32), 25))
			.to.be.revertedWithCustomError(marketv1, "MarketV1JobNotFound");
	});

	it("cannot deposit to closed job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 5000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(50);

		await marketv1.connect(signers[1]).jobReviseRateInitiate(ethers.ZeroHash, 0);
		await time.increase(600);
		await marketv1.connect(signers[1]).jobClose(ethers.ZeroHash);

		await expect(marketv1
			.connect(signers[1])
			.jobDeposit(ethers.ZeroHash, 25))
			.to.be.revertedWithCustomError(marketv1, "MarketV1JobNotFound");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can withdraw from job immediately", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		ts = jobInfo.lastSettled;

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobWithdraw(ethers.ZeroHash, 100);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		let amount = 1n * (jobInfo.lastSettled - ts);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(700n - amount);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(300);
		expect(await pond.balanceOf(addrs[2])).to.equal(amount);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(700n - amount);
	});

	it("can withdraw from job with settlement", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await time.increaseTo(ts + 20n);
		await marketv1
			.connect(signers[1])
			.jobWithdraw(ethers.ZeroHash, 100);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		let amount = 1n * (jobInfo.lastSettled - ts);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(700n - amount);
		expect(jobInfo.lastSettled).to.be.within(ts + 20n, ts + 21n);

		expect(await pond.balanceOf(addrs[1])).to.equal(300);
		expect(await pond.balanceOf(addrs[2])).to.equal(amount);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(700n - amount);
	});

	it("can withdraw from job after a short period with settlement", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await time.increaseTo(ts + 20n);
		await marketv1
			.connect(signers[1])
			.jobWithdraw(ethers.ZeroHash, 100);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		let amount = 1n * (jobInfo.lastSettled - ts);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(700n - amount);
		expect(jobInfo.lastSettled).to.be.within(ts + 20n, ts + 21n);

		expect(await pond.balanceOf(addrs[1])).to.equal(300);
		expect(await pond.balanceOf(addrs[2])).to.equal(amount);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(700n - amount);
	});

	it("cannot withdraw from non existent job", async () => {
		await signers[0].sendTransaction({ to: ethers.ZeroAddress, value: ethers.parseEther("10") })
		let signer = await ethers.getImpersonatedSigner(ethers.ZeroAddress);

		await expect(marketv1
			.connect(signer)
			.jobWithdraw(ethers.ZeroHash, 100))
			.to.be.revertedWithCustomError(marketv1, "MarketV1JobNotFound");
	});

	it("cannot withdraw from third party job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.connect(signers[2])
			.jobWithdraw(ethers.ZeroHash, 100)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});

	it("cannot withdraw if balance is below leftover threshold", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await time.increaseTo(ts + 300n);
		await expect(marketv1
			.connect(signers[1])
			.jobWithdraw(ethers.ZeroHash, 100)).to.be.revertedWithCustomError(marketv1, "MarketV1JobNotEnoughBalance");
	});

	it("cannot withdraw if it puts balance below leftover threshold", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await time.increaseTo(ts + 20n);
		await expect(marketv1
			.connect(signers[1])
			.jobWithdraw(ethers.ZeroHash, 300)).to.be.revertedWithCustomError(marketv1, "MarketV1JobNotEnoughBalance");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can initiate rate revision", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);
	});

	it("cannot initiate rate revision if already initiated", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);
		await expect(marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2)).to.be.revertedWithCustomError(marketv1, "LockShouldBeNone");
	});

	it("cannot initiate rate revision for non existent job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.jobReviseRateInitiate(ethers.zeroPadValue("0x01", 32), 2)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});

	it("cannot initiate rate revision for third party job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.jobReviseRateInitiate(ethers.ZeroHash, 2)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can cancel rate revision", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await marketv1
			.connect(signers[1])
			.jobReviseRateCancel(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);
	});

	it("cannot cancel rate revision if never requested", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.connect(signers[1])
			.jobReviseRateCancel(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "MarketV1JobNoRequest");
	});

	it("cannot cancel rate revision for non existent job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.connect(signers[1])
			.jobReviseRateCancel(ethers.zeroPadValue("0x01", 32))).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});

	it("cannot cancel rate revision for third party job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.jobReviseRateCancel(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can finalize rate revision", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await time.increaseTo(ts + 650n);

		await marketv1
			.connect(signers[1])
			.jobReviseRateFinalize(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		let amount = 1n * (jobInfo.lastSettled - ts);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(2);
		expect(jobInfo.balance).to.equal(800n - amount);
		expect(jobInfo.lastSettled).to.be.within(ts + 650n, ts + 651n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(addrs[2])).to.equal(amount);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800n - amount);
	});

	it("cannot finalize rate revision if never requested", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.connect(signers[1])
			.jobReviseRateFinalize(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "LockShouldBeUnlocked");
	});

	it("cannot finalize rate revision for non existent job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.connect(signers[1])
			.jobReviseRateFinalize(ethers.zeroPadValue("0x01", 32))).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});

	it("cannot finalize rate revision for third party job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.jobReviseRateFinalize(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can close", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 0);

		await time.increaseTo(ts + 650n);

		await marketv1
			.connect(signers[1])
			.jobClose(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x");
		expect(jobInfo.owner).to.equal(ethers.ZeroAddress);
		expect(jobInfo.provider).to.equal(ethers.ZeroAddress);
		expect(jobInfo.rate).to.equal(0);
		expect(jobInfo.balance).to.equal(0);
		expect(jobInfo.lastSettled).to.be.equal(0);

		expect(await pond.balanceOf(addrs[1])).to.be.within(349, 350);
		expect(await pond.balanceOf(addrs[2])).to.be.within(650, 651);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(0);
	});

	it("can close immediately if rate is zero", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 0);

		await time.increaseTo(ts + 650n);

		await marketv1
			.connect(signers[1])
			.jobReviseRateFinalize(ethers.ZeroHash);
		await marketv1
			.connect(signers[1])
			.jobClose(ethers.ZeroHash);

		jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x");
		expect(jobInfo.owner).to.equal(ethers.ZeroAddress);
		expect(jobInfo.provider).to.equal(ethers.ZeroAddress);
		expect(jobInfo.rate).to.equal(0);
		expect(jobInfo.balance).to.equal(0);
		expect(jobInfo.lastSettled).to.be.equal(0);

		expect(await pond.balanceOf(addrs[1])).to.be.within(349, 350);
		expect(await pond.balanceOf(addrs[2])).to.be.within(650, 651);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(0);
	});

	it("cannot close if new rate is not zero", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		ts = jobInfo.lastSettled;

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await time.increaseTo(ts + 650n);

		await expect(marketv1
			.connect(signers[1])
			.jobClose(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "MarketV1JobNonZeroRate");
	});

	it("cannot close if never requested", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await expect(marketv1
			.connect(signers[1])
			.jobClose(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "LockShouldBeUnlocked");
	});

	it("cannot close non existent job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.connect(signers[1])
			.jobClose(ethers.zeroPadValue("0x01", 32))).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});

	it("cannot close third party job", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(await marketv1.getAddress(), 1000);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 1n * 10n ** 12n, 800);

		let jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(1n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(800);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(200);
		expect(await pond.balanceOf(await marketv1.getAddress())).to.equal(800);

		await marketv1
			.connect(signers[1])
			.jobReviseRateInitiate(ethers.ZeroHash, 2);

		await expect(marketv1
			.jobClose(ethers.ZeroHash)).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");
	});
});

describe("MarketV1", function() {
	let signers: Signer[];
	let addrs: string[];
	let marketv1: MarketV1;
	let pond: Contract;

	before(async function() {
		signers = await ethers.getSigners();
		addrs = await Promise.all(signers.map((a) => a.getAddress()));

		const Pond = await ethers.getContractFactory("Pond");
		pond = await upgrades.deployProxy(Pond, ["Marlin", "POND"], {
			kind: "uups",
		});

		const MarketV1 = await ethers.getContractFactory("MarketV1");
		marketv1 = await upgrades.deployProxy(
			MarketV1,
			[addrs[0], await pond.getAddress(), SELECTORS, WAIT_TIMES],
			{ kind: "uups" },
		) as unknown as MarketV1;
		await pond.transfer(addrs[1], 1000);
	});

	takeSnapshotBeforeAndAfterEveryTest(async () => { });

	it("can update metadata", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(marketv1.getAddress(), 100);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		const jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(marketv1.getAddress())).to.equal(50);

		await marketv1
			.connect(signers[1])
			.jobMetadataUpdate(ethers.ZeroHash, "0x0987654321");

		const jobInfo2 = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo2.metadata).to.equal("0x0987654321");

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(marketv1.getAddress())).to.equal(50);
	});

	it("cannot update metadata of other jobs", async () => {
		let ts = toBigInt(Math.floor(Date.now() / 1000) + 86400);
		await time.increaseTo(ts);

		await (pond.connect(signers[1]) as Contract).approve(marketv1.getAddress(), 100);
		await marketv1
			.connect(signers[1])
			.jobOpen("0x1234567890", addrs[2], 5n * 10n ** 12n, 50);

		const jobInfo = await marketv1.jobs(ethers.ZeroHash);
		expect(jobInfo.metadata).to.equal("0x1234567890");
		expect(jobInfo.owner).to.equal(addrs[1]);
		expect(jobInfo.provider).to.equal(addrs[2]);
		expect(jobInfo.rate).to.equal(5n * 10n ** 12n);
		expect(jobInfo.balance).to.equal(50);
		expect(jobInfo.lastSettled).to.be.within(ts, ts + 1n);

		expect(await pond.balanceOf(addrs[1])).to.equal(950);
		expect(await pond.balanceOf(marketv1.getAddress())).to.equal(50);

		await expect(marketv1
			.jobMetadataUpdate(ethers.ZeroHash, "0x0987654321")).to.be.revertedWithCustomError(marketv1, "MarketV1JobOnlyOwner");

	});
});
