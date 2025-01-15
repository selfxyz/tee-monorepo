// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract KmsRootTestConstruction is Test {
    function test_Construction(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        bytes memory _rootKey,
        uint256 _maxAge
    ) public {
        vm.assume(_owner != address(0));

        vm.expectEmit();
        emit Ownable.OwnershipTransferred(address(0), _owner);

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedVerifier(
            _verifier,
            IRiscZeroVerifier(address(0))
        );

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedImageId(_imageId, bytes32(0));

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedPcrs(_pcrs, new bytes(0));

        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedRootKey(_rootKey, new bytes(0));

        KmsRoot _kmsRoot = new KmsRoot(
            _owner,
            _verifier,
            _imageId,
            _pcrs,
            _rootKey,
            _maxAge
        );

        assertEq(_kmsRoot.owner(), _owner);
        assertEq(address(_kmsRoot.verifier()), address(_verifier));
        assertEq(_kmsRoot.imageId(), _imageId);
        assertEq(_kmsRoot.pcrs(), _pcrs);
    }
}

contract KmsRootTestUpdateVerifier is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdateVerifier_FromOwner(IRiscZeroVerifier _verifier) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedVerifier(_verifier, verifier);

        kmsRoot.updateVerifier(_verifier);

        assertEq(address(kmsRoot.verifier()), address(_verifier));
    }

    function test_UpdateVerifier_FromNonOwner(
        IRiscZeroVerifier _verifier,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updateVerifier(_verifier);
    }
}

contract KmsRootTestUpdateImageId is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdateImageId_FromOwner(bytes32 _imageId) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedImageId(_imageId, imageId);

        kmsRoot.updateImageId(_imageId);

        assertEq(kmsRoot.imageId(), _imageId);
    }

    function test_UpdateImageId_FromNonOwner(
        bytes32 _imageId,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updateImageId(_imageId);
    }
}

contract KmsRootTestUpdatePcrs is Test {
    address owner;
    IRiscZeroVerifier verifier;
    bytes32 imageId;
    bytes pcrs;
    bytes rootKey;
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48);
        rootKey = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(owner, verifier, imageId, pcrs, rootKey, maxAge);
    }

    function test_UpdatePcrs_FromOwner(bytes calldata _pcrs) public {
        vm.prank(owner);
        vm.expectEmit();
        emit KmsRoot.KmsRootUpdatedPcrs(_pcrs, pcrs);

        kmsRoot.updatePcrs(_pcrs);

        assertEq(kmsRoot.pcrs(), _pcrs);
    }

    function test_UpdatePcrs_FromNonOwner(
        bytes calldata _pcrs,
        address _nonOwner
    ) public {
        vm.assume(_nonOwner != owner);
        vm.prank(_nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                _nonOwner
            )
        );

        kmsRoot.updatePcrs(_pcrs);
    }
}
