// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";

contract KmsRootTestConstruction is Test {
    function test_Construction(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    ) public {
        vm.assume(_owner != address(0));

        vm.expectEmit();
        emit Ownable.OwnershipTransferred(address(0), _owner);

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, 0);

        KmsRoot _kmsRoot = new KmsRoot(_owner, _verifier, _guestId, _rootKey, _maxAgeMs, _imageId);

        assertEq(_kmsRoot.owner(), _owner);
        assertEq(address(_kmsRoot.verifier()), address(_verifier));
        assertEq(_kmsRoot.guestId(), _guestId);
        assertEq(_kmsRoot.rootKey(), _rootKey);
        assertEq(_kmsRoot.maxAgeMs(), _maxAgeMs);
        assertEq(_kmsRoot.imageId(), _imageId);
    }
}

contract KmsRootTestUpdateVerifier is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(owner, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateVerifier_FromOwner(IRiscZeroVerifier _verifier) public {
        vm.prank(owner);
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, verifier);

        kmsRoot.updateVerifier(_verifier);

        assertEq(address(kmsRoot.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_FromNonOwner(IRiscZeroVerifier _verifier, address _nonOwner) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, _nonOwner));

        kmsRoot.updateVerifier(_verifier);
    }
}

contract KmsRootTestUpdateGuestId is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(owner, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateGuestId_FromOwner(bytes32 _guestId) public {
        vm.prank(owner);
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, guestId);

        kmsRoot.updateGuestId(_guestId);

        assertEq(kmsRoot.guestId(), _guestId);
    }

    function test_UpdateGuestId_FromNonOwner(bytes32 _guestId, address _nonOwner) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, _nonOwner));

        kmsRoot.updateGuestId(_guestId);
    }
}

contract KmsRootTestUpdateRootKey is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(owner, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateRootKey_FromOwner(bytes calldata _rootKey) public {
        vm.prank(owner);
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);

        kmsRoot.updateRootKey(_rootKey);

        assertEq(kmsRoot.rootKey(), _rootKey);
    }

    function test_UpdateRootKey_FromNonOwner(bytes calldata _rootKey, address _nonOwner) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, _nonOwner));

        kmsRoot.updateRootKey(_rootKey);
    }
}

contract KmsRootTestUpdateMaxAge is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        imageId = bytes32(vm.randomUint());
        kmsRoot = new KmsRoot(owner, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_UpdateMaxAge_FromOwner(uint256 _maxAgeMs) public {
        vm.prank(owner);
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, maxAgeMs);

        kmsRoot.updateMaxAge(_maxAgeMs);

        assertEq(kmsRoot.maxAgeMs(), _maxAgeMs);
    }

    function test_UpdateMaxAge_FromNonOwner(uint256 _maxAgeMs, address _nonOwner) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, _nonOwner));

        kmsRoot.updateMaxAge(_maxAgeMs);
    }
}

contract KmsRootTestVerify is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        kmsRoot = new KmsRoot(owner, verifier, guestId, rootKey, maxAgeMs, imageId);
    }

    function test_Verify_Valid(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        bytes32 _journalDigest =
            sha256(abi.encodePacked(_timestampInMilliseconds, rootKey, uint8(64), _pubkey, _imageId));
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        address _addr = address(uint160(uint256(keccak256(_pubkey))));
        vm.expectEmit();
        emit KmsRoot.KmsRootVerified(_addr);
        vm.warp(4);

        kmsRoot.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);

        assertTrue(kmsRoot.isVerified(_addr));
    }

    function test_Verify_TooOld(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 0, 2000));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierTooOld.selector));
        vm.warp(4);

        kmsRoot.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }

    function test_Verify_InvalidLength(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length != 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        vm.expectRevert(abi.encodeWithSelector(KmsRoot.KmsRootLengthInvalid.selector));
        vm.warp(4);

        kmsRoot.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }

    function test_Verify_InvalidSeal(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        vm.mockCallRevert(address(verifier), abi.encode(), "0x12345678");
        vm.expectRevert("0x12345678");
        vm.warp(4);

        kmsRoot.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }
}
