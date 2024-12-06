// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface ISecretStoreManager {
    function register(address _enclaveAddress, uint256 _storageCapacity) external;

    function getSecretStoreStorageData(
        address _enclaveAddress
    ) external returns (uint256 storageCapacity, uint256 storageOccupied);
}
