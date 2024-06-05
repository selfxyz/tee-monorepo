// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract JobsMock {
    error JobsMockError();

    function createJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline // in milliseconds
    ) external returns (uint256) {
        revert JobsMockError();
    }
}
