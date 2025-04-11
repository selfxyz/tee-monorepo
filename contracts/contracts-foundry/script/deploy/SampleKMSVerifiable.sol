// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import "forge-std/Script.sol";
import "../../src/kms/SampleKMSVerifiable.sol";

contract SampleKMSVerifiableScript is Script {
    function run() external returns (SampleKMSVerifiable) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(privateKey);
        bytes32 [] memory _imageIds = new bytes32[](0);
        SampleKMSVerifiable sampleKmsVerifiable = new SampleKMSVerifiable(_imageIds);
        vm.stopBroadcast();
        console.log("Deployed to:", address(sampleKmsVerifiable));

        return sampleKmsVerifiable;
    }
}
