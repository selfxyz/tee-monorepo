// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

interface ISecretStore {
    // function getStakeAmount(address _enclaveAddress) external returns (uint256);

    // function setStakeAmount(address _enclaveAddress, uint256 _value) external;

    function getOwner(address _enclaveAddress) external view returns (address);

    function selectNodes(uint8 _env, uint256 _noOfNodesToSelect) external view returns (address[] memory selectedNodes);

    function updateTreeState(address _enclaveAddress) external;

    function slashStore(address _enclaveAddress, uint256 _missedEpochsCount, address _recipient) external;

    function deleteIfPresent(uint8 _env, address _enclaveAddress) external;
}
