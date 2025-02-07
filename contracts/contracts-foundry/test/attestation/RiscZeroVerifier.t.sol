// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract TestRiscZeroVerifier is RiscZeroVerifier {
    bool public authorized;

    error NotAuthorized();

    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bool _authorized
    ) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) {
        authorized = _authorized;
    }

    function setAuthorized(bool _authorized) external {
        authorized = _authorized;
    }

    function _authorizeRiscZeroUpdate() internal virtual override {
        require(authorized, NotAuthorized());
    }

    function verify(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampInMilliseconds)
        external
    {
        return _verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }
}

contract RiscZeroVerifierTestConstruction is Test {
    function test_Construction(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAgeMs)
        public
    {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, 0);

        TestRiscZeroVerifier _riscZeroVerifier =
            new TestRiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs, true);

        assertEq(address(_riscZeroVerifier.verifier()), address(_verifier));
        assertEq(_riscZeroVerifier.guestId(), _guestId);
        assertEq(_riscZeroVerifier.rootKey(), _rootKey);
        assertEq(_riscZeroVerifier.maxAgeMs(), _maxAgeMs);
    }
}

contract RiscZeroVerifierTestUpdateVerifier is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateVerifier_Authorized(IRiscZeroVerifier _verifier) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, verifier);

        riscZeroVerifier.updateVerifier(_verifier);

        assertEq(address(riscZeroVerifier.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_Unauthorized(IRiscZeroVerifier _verifier) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateVerifier(_verifier);
    }
}

contract RiscZeroVerifierTestUpdateGuestId is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateGuestId_Authorized(bytes32 _guestId) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, guestId);

        riscZeroVerifier.updateGuestId(_guestId);

        assertEq(riscZeroVerifier.guestId(), _guestId);
    }

    function test_UpdateGuestId_Unauthorized(bytes32 _guestId) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateGuestId(_guestId);
    }
}

contract RiscZeroVerifierTestUpdateRootKey is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateRootKey_Authorized(bytes calldata _rootKey) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);

        riscZeroVerifier.updateRootKey(_rootKey);

        assertEq(riscZeroVerifier.rootKey(), _rootKey);
    }

    function test_UpdateRootKey_Unauthorized(bytes calldata _rootKey) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateRootKey(_rootKey);
    }
}

contract RiscZeroVerifierTestUpdateMaxAge is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = vm.randomUint();
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_UpdateMaxAge_Authorized(uint256 _maxAgeMs) public {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, maxAgeMs);

        riscZeroVerifier.updateMaxAge(_maxAgeMs);

        assertEq(riscZeroVerifier.maxAgeMs(), _maxAgeMs);
    }

    function test_UpdateMaxAge_Unauthorized(uint256 _maxAgeMs) public {
        riscZeroVerifier.setAuthorized(false);
        vm.expectRevert(TestRiscZeroVerifier.NotAuthorized.selector);

        riscZeroVerifier.updateMaxAge(_maxAgeMs);
    }
}

contract RiscZeroVerifierTestVerify is Test {
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    TestRiscZeroVerifier riscZeroVerifier;

    function setUp() public {
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        riscZeroVerifier = new TestRiscZeroVerifier(verifier, guestId, rootKey, maxAgeMs, true);
    }

    function test_Verify_Valid(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length <= 256);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        bytes32 _journalDigest =
            sha256(abi.encodePacked(_timestampInMilliseconds, rootKey, uint8(_pubkey.length), _pubkey, _imageId));
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata =
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        vm.expectCall(address(verifier), _calldata, 1);
        vm.warp(4);

        riscZeroVerifier.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }

    function test_Verify_TooOld(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length <= 256);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 0, 2000));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierTooOld.selector));
        vm.warp(4);

        riscZeroVerifier.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }

    function test_Verify_TooLong(
        bytes calldata _seal,
        bytes memory _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        // foundry does not generate data >256 length, concat to emulate it
        vm.assume(_pubkey.length > 64);
        _pubkey = bytes.concat(_pubkey, _pubkey, _pubkey, _pubkey);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        vm.expectRevert(abi.encodeWithSelector(RiscZeroVerifier.RiscZeroVerifierPubkeyTooLong.selector));
        vm.warp(4);

        riscZeroVerifier.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }

    function test_Verify_InvalidSeal(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length <= 256);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        vm.mockCallRevert(address(verifier), abi.encode(), "0x12345678");
        vm.expectRevert("0x12345678");
        vm.warp(4);

        riscZeroVerifier.verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
    }
}
