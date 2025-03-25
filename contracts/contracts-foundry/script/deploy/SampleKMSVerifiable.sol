// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "../../src/kms/SampleKMSVerifiable.sol";

contract SampleKMSVerifiableScript is Script {
    function run() external returns (SampleKMSVerifiable) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        bytes32 [] memory _imageIds = new bytes32[](0);
        address admin = address(0xE249E8d4618E77E0a5B52156B0483E5CAEaFFc88);
        // address admin = address(0x0A6f4582b04aBb0aaD587d39B52e769A569A6856);
        SampleKMSVerifiable sampleKmsVerifiable = new SampleKMSVerifiable( admin, _imageIds);
        vm.stopBroadcast();
        console.log("Deployed to:", address(sampleKmsVerifiable));

        return sampleKmsVerifiable;
    }
}
