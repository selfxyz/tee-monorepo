// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {IAccessControl} from "../../lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationVerifier} from "../../src/attestation/AttestationVerifier.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";
import {VerifiedKeys} from "../../src/attestation/VerifiedKeys.sol";

contract TestAttestationVerifier is AttestationVerifier {
    bool public shouldVerify;

    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
    ) AttestationVerifier(_admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId, _family) {
        shouldVerify = true;
    }

    function setShouldVerify(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }
}

contract AttestationVerifierTestConstruction is Test {
    function test_Construction(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
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
        emit VerifiedKeys.VerifiedKeysApproved(_imageId, _family);

        vm.expectEmit();
        emit IAccessControl.RoleGranted(bytes32(0), _admin, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("APPROVER_ROLE"), _approver, address(this));
        vm.expectEmit();
        emit IAccessControl.RoleGranted(keccak256("REVOKER_ROLE"), _revoker, address(this));

        TestAttestationVerifier verifier = new TestAttestationVerifier(
            _admin, _approver, _revoker, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId, _family
        );

        assertEq(address(verifier.verifier()), address(_verifier));
        assertEq(verifier.guestId(), _guestId);
        assertEq(verifier.rootKey(), _rootKey);
        assertEq(verifier.maxAgeMs(), _maxAgeMs);
        assertEq(verifier.images(_imageId), _family);
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(verifier.hasRole(verifier.APPROVER_ROLE(), _approver));
        assertTrue(verifier.hasRole(verifier.REVOKER_ROLE(), _revoker));
    }
}

contract AttestationVerifierTestVerify is Test {
    TestAttestationVerifier verifier;
    address admin = makeAddr("admin");
    address approver = makeAddr("approver");
    address revoker = makeAddr("revoker");
    IRiscZeroVerifier riscZeroVerifier = IRiscZeroVerifier(makeAddr("verifier"));
    bytes32 guestId = bytes32(uint256(1));
    bytes rootKey = hex"010203";
    uint256 maxAgeMs = 1000;
    bytes32 imageId = bytes32(uint256(2));
    bytes32 family = bytes32(uint256(3));

    function setUp() public {
        verifier = new TestAttestationVerifier(
            admin, approver, revoker, riscZeroVerifier, guestId, rootKey, maxAgeMs, imageId, family
        );
    }

    function createAttestation(bytes memory pubkey, uint64 timestamp)
        internal
        view
        returns (IAttestationVerifier.Attestation memory)
    {
        return IAttestationVerifier.Attestation({
            enclavePubKey: pubkey,
            imageId: imageId,
            timestampInMilliseconds: timestamp
        });
    }

    function test_Verify_ValidSignature(bytes memory signature, bytes memory pubkey, uint64 timestamp) public {
        vm.assume(pubkey.length == 64);
        timestamp = uint64(bound(timestamp, block.timestamp * 1000 - maxAgeMs + 1, type(uint64).max));

        vm.prank(approver);
        verifier.approveImage(imageId, family);

        verifier.verify(signature, createAttestation(pubkey, timestamp));
    }

    function test_Verify_InvalidSignature(bytes memory signature, bytes memory pubkey, uint64 timestamp) public {
        vm.assume(pubkey.length == 64);
        timestamp = uint64(bound(timestamp, block.timestamp * 1000 - maxAgeMs + 1, type(uint64).max));

        verifier.setShouldVerify(false);
        vm.expectRevert("not verified");
        verifier.verify(signature, createAttestation(pubkey, timestamp));
    }

    function test_Verify_ExpiredSignature(bytes memory signature, bytes memory pubkey, uint64 timestamp) public {
        vm.assume(pubkey.length == 64);
        timestamp = uint64(bound(timestamp, 0, block.timestamp * 1000 - maxAgeMs));

        vm.expectRevert("AttestationAutherTooOld()");
        verifier.verify(signature, createAttestation(pubkey, timestamp));
    }

    function test_Verify_RevokedKey(bytes memory signature, bytes memory pubkey, uint64 timestamp) public {
        vm.assume(pubkey.length == 64);
        timestamp = uint64(bound(timestamp, block.timestamp * 1000 - maxAgeMs + 1, type(uint64).max));

        vm.prank(approver);
        verifier.approveImage(imageId, family);
        vm.prank(revoker);
        verifier.revokeImage(imageId);

        vm.expectRevert("VerifiedKeysNotVerified()");
        verifier.verify(signature, createAttestation(pubkey, timestamp));
    }
}
