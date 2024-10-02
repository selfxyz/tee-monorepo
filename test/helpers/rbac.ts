import { expect } from "chai";
import { Contract, Signer } from "ethers";
import { ethers, network } from "hardhat";

export function testAdminRole(name: string, deployer: (signers: Signer[], addrs: string[]) => Promise<Contract>) {
    describe(name, function () {
        let signers: Signer[];
        let addrs: string[];
        let contract: Contract;
        let DEFAULT_ADMIN_ROLE: string;

        let snapshot: any;

        before(async function () {
            signers = await ethers.getSigners();
            addrs = await Promise.all(signers.map((a) => a.getAddress()));
            contract = await deployer(signers, addrs);
            DEFAULT_ADMIN_ROLE = await contract.DEFAULT_ADMIN_ROLE();
        });

        beforeEach(async function () {
            snapshot = await network.provider.request({
                method: "evm_snapshot",
                params: [],
            });
        });

        afterEach(async function () {
            await network.provider.request({
                method: "evm_revert",
                params: [snapshot],
            });
        });

        it("admin can grant admin role", async function () {
            await contract.grantRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.true;
        });

        it("non admin cannot grant admin role", async function () {
            await expect((contract.connect(signers[1]) as Contract).grantRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.reverted;
        });

        it("admin can revoke admin role", async function () {
            await contract.grantRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.true;

            await contract.revokeRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.false;
        });

        it("non admin cannot revoke admin role", async function () {
            await contract.grantRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.true;

            await expect((contract.connect(signers[2]) as Contract).revokeRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.reverted;
        });

        it("admin can renounce own admin role if there are other admins", async function () {
            await contract.grantRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.true;

            await (contract.connect(signers[1]) as Contract).renounceRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.false;
        });

        it("admin can renounce own admin role even if there are no other admins", async function () {
            await contract.renounceRole(DEFAULT_ADMIN_ROLE, addrs[0]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[0])).to.be.false;
        });

        it("admin cannot renounce admin role of other admins", async function () {
            await contract.grantRole(DEFAULT_ADMIN_ROLE, addrs[1]);
            expect(await contract.hasRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.true;

            await expect(contract.renounceRole(DEFAULT_ADMIN_ROLE, addrs[1])).to.be.reverted;
        });
    });
}

export function testRole(name: string, deployer: (signers: Signer[], addrs: string[]) => Promise<Contract>, role: string) {
    describe(name, function () {
        let signers: Signer[];
        let addrs: string[];
        let contract: Contract;
        let ROLE: string;

        let snapshot: any;

        before(async function () {
            signers = await ethers.getSigners();
            addrs = await Promise.all(signers.map((a) => a.getAddress()));
            contract = await deployer(signers, addrs);
            ROLE = await contract[role]();
        });

        beforeEach(async function () {
            snapshot = await network.provider.request({
                method: "evm_snapshot",
                params: [],
            });
        });

        afterEach(async function () {
            await network.provider.request({
                method: "evm_revert",
                params: [snapshot],
            });
        });

        it(`admin can grant ${role} role`, async function () {
            await contract.grantRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.true;
        });

        it(`non admin cannot grant ${role} role`, async function () {
            await expect((contract.connect(signers[1]) as Contract).grantRole(ROLE, addrs[1])).to.be.reverted;
        });

        it(`admin can revoke ${role} role`, async function () {
            await contract.grantRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.true;

            await contract.revokeRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.false;
        });

        it(`non admin cannot revoke ${role} role`, async function () {
            await contract.grantRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.true;

            await expect((contract.connect(signers[2]) as Contract).revokeRole(ROLE, addrs[1])).to.be.reverted;
        });

        it(`${role} signer can renounce own ${role} role`, async function () {
            await contract.grantRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.true;

            await (contract.connect(signers[1]) as Contract).renounceRole(ROLE, addrs[1]);
            expect(await contract.hasRole(ROLE, addrs[1])).to.be.false;
        });
    });
}
