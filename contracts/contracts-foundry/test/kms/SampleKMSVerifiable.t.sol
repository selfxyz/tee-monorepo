// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {SampleKMSVerifiable} from "../../src/kms/SampleKMSVerifiable.sol";

contract SampleKMSVerifiableTestConstructor is Test {
    function test_construction(
        address _admin
    ) public {
        bytes32 [] memory _imageIds = new bytes32[](1);
        _imageIds[0] = bytes32(vm.randomUint());
        SampleKMSVerifiable _kms = new SampleKMSVerifiable(_admin, _imageIds);
        assertTrue(_kms.hasRole(_kms.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(_kms.images(_imageIds[0]));
    }
}

contract SampleKMSVerifiableTest is Test {
    address admin;
    bytes32[] imageIds;
    SampleKMSVerifiable kmsVerifiable;
    function setUp() public {
        admin = makeAddr("admin");
        imageIds = new bytes32[](1);
        imageIds[0] = bytes32(vm.randomUint());
        kmsVerifiable = new SampleKMSVerifiable(admin, imageIds);
    }

    function test_verifyImage() public view {
        // Execute
        bytes32 imageId = imageIds[0];
        bool result = kmsVerifiable.oysterKMSVerify(imageId);
        // Validate
        assertTrue(result);
    }

    function test_whitelistImages(bytes32[] calldata _imageIds) public {
        // Execute
        vm.prank(admin);
        kmsVerifiable.whitelistImages(_imageIds);
        // Validate
        for (uint i = 0; i < _imageIds.length; i++) {
            assertTrue(kmsVerifiable.images(_imageIds[i]));
        }

        // whitelist the same images again
        vm.prank(admin);
        kmsVerifiable.whitelistImages(_imageIds);
        for (uint i = 0; i < _imageIds.length; i++) {
            assertTrue(kmsVerifiable.images(_imageIds[i]));
        }
    }

    function test_blacklistImages() public {
        // Execute
        vm.prank(admin);
        kmsVerifiable.blacklistImages(imageIds);
        // Validate
        for (uint i = 0; i < imageIds.length; i++) {
            assertFalse(kmsVerifiable.images(imageIds[i]));
        }

        // blacklist the same images again
        vm.prank(admin);
        kmsVerifiable.blacklistImages(imageIds);
        for (uint i = 0; i < imageIds.length; i++) {
            assertFalse(kmsVerifiable.images(imageIds[i]));
        }
    }

}