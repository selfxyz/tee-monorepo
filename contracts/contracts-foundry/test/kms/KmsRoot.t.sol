// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {KmsRoot} from "../../src/kms/KmsRoot.sol";

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
