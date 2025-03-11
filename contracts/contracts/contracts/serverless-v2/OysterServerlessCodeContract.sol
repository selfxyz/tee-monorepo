/**
 *Submitted for verification at Sepolia.Arbiscan.io on 2023-12-25
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OysterServerlessCodeContract {

    event CodeCreated(bytes indexed metadata);

    function saveCodeInCallData(string calldata inputData, bytes calldata metadata) external {
        emit CodeCreated(metadata);
    }
}