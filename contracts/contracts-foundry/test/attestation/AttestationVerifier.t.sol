// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {IAccessControl} from "../../lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationVerifier} from "../../src/attestation/AttestationVerifier.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";
import {VerifiedKeys} from "../../src/attestation/VerifiedKeys.sol";

contract AttestationVerifierTestConstruction is Test {
    function test_Construction(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    ) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, 0);

        vm.expectEmit();
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, keccak256("DEFAULT_FAMILY"));

        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("APPROVER_ROLE"), _approver, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("REVOKER_ROLE"), _revoker, address(this));

        AttestationVerifier verifier =
            new AttestationVerifier(_admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId);

        assertEq(address(verifier.verifier()), address(_verifier));
        assertEq(verifier.guestId(), _guestId);
        assertEq(verifier.rootKey(), _rootKey);
        assertEq(verifier.maxAgeMs(), _maxAgeMs);
        assertEq(verifier.images(_imageId), keccak256("DEFAULT_FAMILY"));
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(verifier.hasRole(verifier.APPROVER_ROLE(), _approver));
        assertTrue(verifier.hasRole(verifier.REVOKER_ROLE(), _revoker));
    }
}

contract AttestationVerifierTestVerify is Test {
    AttestationVerifier verifier;
    address admin = makeAddr("admin");
    address approver = makeAddr("approver");
    address revoker = makeAddr("revoker");
    IRiscZeroVerifier riscZeroVerifier = IRiscZeroVerifier(makeAddr("verifier"));
    bytes32 guestId = bytes32(uint256(1));
    bytes rootKey = hex"010203";
    uint256 maxAgeMs = 2000;
    bytes32 imageId = bytes32(uint256(2));

    function setUp() public {
        verifier =
            new AttestationVerifier(admin, approver, revoker, riscZeroVerifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_Verify_ValidSignature() public {
        // generated using attestation-verifier.test.js
        bytes memory _pubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        uint256 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"b5a9242c39d6e01a6b204ad7495081b56ac9f6dfadc9eaa04c2f3052ab328fbc41fa56be313d0164ec7b0bc0696a191653bc8ddcc246a73dc375decfff8a90f61b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(_pubkey, imageId, _timestamp);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclave(_signature, _pubkey, imageId, uint64(_timestamp));

        verifier.verify(_signature, attestation);
    }

    function test_Verify_InvalidSignature() public {
        // generated using attestation-verifier.test.js
        bytes memory _pubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        uint256 _timestamp = 0x4e43046b;
        // modified last - 1 byte
        bytes memory _signature =
            hex"b5a9242c39d6e01a6b204ad7495081b56ac9f6dfadc9eaa04c2f3052ab328fbc41fa56be313d0164ec7b0bc0696a191653bc8ddcc246a73dc375decfff8a90f51b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(_pubkey, imageId, _timestamp);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclave(_signature, _pubkey, imageId, uint64(_timestamp));
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }

    function test_Verify_UnverifiedKey() public {
        // generated using attestation-verifier.test.js
        bytes memory _pubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        uint256 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"b5a9242c39d6e01a6b204ad7495081b56ac9f6dfadc9eaa04c2f3052ab328fbc41fa56be313d0164ec7b0bc0696a191653bc8ddcc246a73dc375decfff8a90f61b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(_pubkey, imageId, _timestamp);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }

    function test_Verify_RevokedKey() public {
        // generated using attestation-verifier.test.js
        bytes memory _pubkey =
            hex"9d17c9747a93e74b4065164eaf1df2e22bd36dc17772cf3fb99bfe6ff47bbd3ce8034234fa46b89c99d6e81393e60e7bcc83680e7b15bfd0fbcb01ae78aa9c76";
        uint256 _timestamp = 0x4e43046b;
        bytes memory _signature =
            hex"b5a9242c39d6e01a6b204ad7495081b56ac9f6dfadc9eaa04c2f3052ab328fbc41fa56be313d0164ec7b0bc0696a191653bc8ddcc246a73dc375decfff8a90f61b";
        IAttestationVerifier.Attestation memory attestation =
            IAttestationVerifier.Attestation(_pubkey, imageId, _timestamp);
        vm.mockCall(address(riscZeroVerifier), abi.encode(), abi.encode());
        vm.warp(_timestamp / 1000);
        verifier.verifyEnclave(_signature, _pubkey, imageId, uint64(_timestamp));
        vm.prank(revoker);
        verifier.revokeImage(imageId);
        vm.expectRevert(VerifiedKeys.VerifiedKeysNotVerified.selector);

        verifier.verify(_signature, attestation);
    }
}
