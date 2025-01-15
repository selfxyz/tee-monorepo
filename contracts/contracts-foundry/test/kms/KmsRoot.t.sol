// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

import "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract KmsRootTestConstruction is Test {
    function test_Construction(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        uint256 _maxAge
    ) public {
        vm.assume(_owner != address(0));

        vm.expectEmit();
        emit Ownable.OwnershipTransferred(address(0), _owner);

        vm.expectEmit();
        emit KmsRoot.KmsRootVerifierUpdated(
            _verifier,
            IRiscZeroVerifier(address(0))
        );

        vm.expectEmit();
        emit KmsRoot.KmsRootImageIdUpdated(_imageId, bytes32(0));

        vm.expectEmit();
        emit KmsRoot.KmsRootPcrsUpdated(_pcrs, new bytes(0));

        KmsRoot _kmsRoot = new KmsRoot(
            _owner,
            _verifier,
            _imageId,
            _pcrs,
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
    uint256 maxAge;
    KmsRoot kmsRoot;

    function setUp() public {
        owner = makeAddr("owner");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        imageId = bytes32(vm.randomUint());
        pcrs = vm.randomBytes(48);
        maxAge = vm.randomUint();
        kmsRoot = new KmsRoot(
            makeAddr("owner"),
            IRiscZeroVerifier(makeAddr("verifier")),
            bytes32(vm.randomUint()),
            vm.randomBytes(48),
            vm.randomUint()
        );
    }

    function test_UpdateVerifier_FromOwner(IRiscZeroVerifier _verifier) public {
        vm.prank(owner);

        kmsRoot.updateVerifier(_verifier);

        assertEq(address(kmsRoot.verifier()), address(_verifier));
    }
}
