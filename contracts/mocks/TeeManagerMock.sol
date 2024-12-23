// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "../secret-storage/SecretStore.sol";
import "../secret-storage/Executors.sol";
import "@openzeppelin/contracts/utils/Context.sol";

contract TeeManagerMock is Context {

    Executors public EXECUTORS;
    SecretStore public SECRET_STORE;
    uint256 public immutable MIN_STAKE_AMOUNT;

    struct TeeNode {
        uint256 stakeAmount;
        address owner;
        uint8 env;
        bool draining;
    }

    // enclaveAddress => TEE node details
    mapping(address => TeeNode) public teeNodes;

    constructor(
        uint256 _minStakeAmount
    ) {
        MIN_STAKE_AMOUNT = _minStakeAmount;
    }

    function setExecutors(Executors _executors) external {
        EXECUTORS = _executors;
    }

    function setSecretStore(SecretStore _secretStore) external {
        SECRET_STORE = _secretStore;
    }

    // --------------------------------- Executors functions start ---------------------------------

    function registerExecutor(
        address _enclaveAddress,
        uint256 _jobCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        teeNodes[_enclaveAddress].env = _env;
        teeNodes[_enclaveAddress].owner = _msgSender();
        teeNodes[_enclaveAddress].stakeAmount = _stakeAmount;

        EXECUTORS.registerExecutor(_enclaveAddress, _jobCapacity, _env, _stakeAmount);
    }

    function deregisterExecutor(address _enclaveAddress) external {
        EXECUTORS.deregisterExecutor(_enclaveAddress);
    }

    function drainExecutor(
        address _enclaveAddress,
        uint8 _env
    ) external {
        EXECUTORS.drainExecutor(_enclaveAddress, _env);
    }

    function reviveExecutor(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        EXECUTORS.reviveExecutor(_enclaveAddress, _env, _stakeAmount);
    }

    function addExecutorStake(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) external {
        EXECUTORS.addExecutorStake(_enclaveAddress, _env, _stake);
    }

    function removeExecutorStake(
        address _enclaveAddress
    ) external view {
        EXECUTORS.removeExecutorStake(_enclaveAddress);
    }

    function slashExecutor(
        address _enclaveAddress,
        address _recipient
    ) external returns (uint256) {
        return 0;
    }

    // ---------------------------------- Executors functions end -------------------------------------

    // --------------------------------- Secret Store functions start ---------------------------------

    function registerSecretStore(
        address _enclaveAddress,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        teeNodes[_enclaveAddress].env = _env;
        teeNodes[_enclaveAddress].owner = _msgSender();
        teeNodes[_enclaveAddress].stakeAmount = _stakeAmount;

        SECRET_STORE.registerSecretStore(
            _enclaveAddress,
            _storageCapacity,
            _env,
            _stakeAmount
        );
    }

    function deregisterSecretStore(address _enclaveAddress) external {
        SECRET_STORE.deregisterSecretStore(_enclaveAddress);
    }

    function drainSecretStore(
        address _enclaveAddress,
        uint8 _env
    ) external {
        SECRET_STORE.drainSecretStore(_enclaveAddress, _env);
    }

    function reviveSecretStore(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        SECRET_STORE.reviveSecretStore(_enclaveAddress, _env, _stakeAmount);
    }

    function addSecretStoreStake(
        address _enclaveAddress,
        uint8 _env,
        uint256 _stake
    ) external {
        SECRET_STORE.addSecretStoreStake(_enclaveAddress, _env, _stake);
    }

    function removeSecretStoreStake(
        address _enclaveAddress
    ) external view {
        SECRET_STORE.removeSecretStoreStake(_enclaveAddress);
    }

    function slashStore(
        address _enclaveAddress,
        uint256 _missedEpochsCount,
        address _recipient
    ) external {}

    // --------------------------------- Secret Store functions end ---------------------------------

    function getTeeNodesStake(
        address[] memory _enclaveAddresses
    ) external view returns (uint256[] memory) {
        uint256 len = _enclaveAddresses.length;
        uint256[] memory stakeAmounts = new uint256[](len);
        for (uint256 index = 0; index < len; index++)
            stakeAmounts[index] = teeNodes[_enclaveAddresses[index]].stakeAmount;

        return stakeAmounts;
    }

}