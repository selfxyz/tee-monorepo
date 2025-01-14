// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/Context.sol";
// import "../secret-storage/SecretStore.sol";
import "../secret-storage/SecretManager.sol";

contract SecretStoreMock is Context {

    constructor() {}

    SecretManager public SECRET_MANAGER;

    struct SecretStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 lastAliveTimestamp;
        uint256 deadTimestamp;
        uint256[] ackSecretIds;
    }

    // enclaveAddress => Storage node details
    mapping(address => SecretStorage) public secretStores;

    function setSecretManager(address _secretManagerAddress) external {
        SECRET_MANAGER = SecretManager(_secretManagerAddress);
    }

    function registerSecretStore(
        address _enclaveAddress,
        uint256 _storageCapacity,
        uint8 _env,
        uint256 _stakeAmount
    ) external {
        secretStores[_enclaveAddress].storageCapacity = _storageCapacity;
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;
    }

    function selectNonAssignedSecretStore(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit,
        address[] memory _selectedStoresToIgnore
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        SecretManager.SelectedEnclave[] memory selectedStores = new SecretManager.SelectedEnclave[](1);
        selectedStores[0] = SecretManager.SelectedEnclave({
            enclaveAddress: address(1),
            hasAcknowledgedStore: true,
            selectTimestamp: block.timestamp,
            replacedAckTimestamp: 0
        });
        return selectedStores;
    }

    function selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external returns (SecretManager.SelectedEnclave[] memory) {
        SecretManager.SelectedEnclave[] memory selectedStores = new SecretManager.SelectedEnclave[](_noOfNodesToSelect);
        for (uint256 index = 0; index < _noOfNodesToSelect; index++) {
            selectedStores[index] = SecretManager.SelectedEnclave({
                enclaveAddress: storesToSelect[index],
                hasAcknowledgedStore: false,
                selectTimestamp: block.timestamp,
                replacedAckTimestamp: 0
            });
            secretStores[storesToSelect[index]].storageOccupied += _sizeLimit;
        }
        return selectedStores;
    }

    function renounceSecrets(
        address _enclaveAddress,
        address _owner
    ) external returns (uint256 /* occupiedStorage */) {
        uint256 lastAliveTimestamp = secretStores[_enclaveAddress].lastAliveTimestamp;
        // pre-update
        secretStores[_enclaveAddress].lastAliveTimestamp = block.timestamp;

        uint256 occupiedStorage = SECRET_MANAGER.renounceSecrets(
            _enclaveAddress,
            _owner,
            secretStores[_enclaveAddress].ackSecretIds,
            lastAliveTimestamp
        );

        // post-update
        secretStores[_enclaveAddress].storageOccupied -= occupiedStorage;
        delete secretStores[_enclaveAddress].ackSecretIds;

        return occupiedStorage;
    }

    function addAckSecretIdToStore(
        address _enclaveAddress,
        uint256 _ackSecretId
    ) external {
        secretStores[_enclaveAddress].ackSecretIds.push(_ackSecretId);
    }

    address[] public storesToSelect;

    function setStoresToSelect(
        address[] memory _stores
    ) external {
        storesToSelect = _stores;
    }

    function markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) external {
        secretStores[_enclaveAddress].lastAliveTimestamp = _currentCheckTimestamp;
    }

    function getSecretStoreLastAliveTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStores[_enclaveAddress].lastAliveTimestamp;
    }

    function getSecretStoreDeadTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStores[_enclaveAddress].deadTimestamp;
    }

    function getStoreAckSecretIds(address _enclaveAddress) external view returns (uint256[] memory) {
        return secretStores[_enclaveAddress].ackSecretIds;
    }

}