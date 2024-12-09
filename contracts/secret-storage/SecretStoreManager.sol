// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./SecretManager.sol";
import "./interfaces/ISecretStore.sol";

/**
 * @title SecretManagerStore Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract SecretStoreManager is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{

    /// @notice Thrown when the provided secret store contract address is zero.
    error SecretStoreManagerZeroAddressSecretStore();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param _secretStoreAddress The secret store contract address.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _secretStoreAddress
    ) {
        _disableInitializers();

        if (address(_secretStoreAddress) == address(0)) revert SecretStoreManagerZeroAddressSecretStore();
        
        SECRET_STORE = ISecretStore(_secretStoreAddress);
    }

    //-------------------------------- Overrides start --------------------------------//

    /// @inheritdoc ERC165Upgradeable
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @inheritdoc UUPSUpgradeable
    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    /// @notice Thrown when the provided admin address is zero.
    error SecretStoreManagerZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert SecretStoreManagerZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    bytes32 public constant SECRET_MANAGER_ROLE = keccak256("SECRET_MANAGER_ROLE");

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    ISecretStore public immutable SECRET_STORE;

    //-------------------------------- SecretStore start --------------------------------//

    modifier onlySecretStore() {
        if(_msgSender() != address(SECRET_STORE))
            revert SecretStoreManagerInvalidSecretStore();
        _;
    }

    struct SecretStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 lastAliveTimestamp;
        uint256 deadTimestamp;
        uint256[] ackSecretIds;
    }

    // enclaveAddress => Storage node details
    mapping(address => SecretStorage) public secretStorage;

    error SecretStoreManagerInvalidSecretStore();

    //----------------------------------- SecretStore end -----------------------------------------//

    //----------------------------- SecretManagerRole functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _register(
        address _enclaveAddress,
        uint256 _storageCapacity
    ) internal {
        secretStorage[_enclaveAddress].storageCapacity = _storageCapacity;
        secretStorage[_enclaveAddress].lastAliveTimestamp = block.timestamp;
    }

    function _selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) internal returns (SecretManager.SelectedEnclave[] memory) {
        address[] memory selectedNodes = SECRET_STORE.selectNodes(_env, _noOfNodesToSelect);

        uint len = selectedNodes.length;
        SecretManager.SelectedEnclave[] memory  selectedEnclaves = new SecretManager.SelectedEnclave[](len);
        for (uint256 index = 0; index < len; index++) {
            address enclaveAddress = selectedNodes[index];
            secretStorage[enclaveAddress].storageOccupied += _sizeLimit;

            SecretManager.SelectedEnclave memory selectedEnclave;
            selectedEnclave.enclaveAddress = enclaveAddress;
            selectedEnclave.selectTimestamp = block.timestamp;
            selectedEnclaves[index] = selectedEnclave;

            // TODO: need to have some buffer space for each enclave
            if (secretStorage[enclaveAddress].storageOccupied >= secretStorage[enclaveAddress].storageCapacity)
                SECRET_STORE.deleteIfPresent(_env, enclaveAddress);
        }
        return selectedEnclaves;
    }

    function _slashStore(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        uint256 lastAliveTimestamp = secretStorage[_enclaveAddress].lastAliveTimestamp;
        uint256 deadTimestamp = secretStorage[_enclaveAddress].deadTimestamp;
        uint256 lastCheckTimestamp = (lastAliveTimestamp > deadTimestamp) ? lastAliveTimestamp : deadTimestamp;
        uint256 missedEpochsCount = (_currentCheckTimestamp - lastCheckTimestamp) / _markAliveTimeout;

        if(missedEpochsCount > 0)
            SECRET_STORE.slashStore(_enclaveAddress, missedEpochsCount, _recipient);
    }

    function _releaseStore(
        address _enclaveAddress,
        uint256 _secretSize
    ) internal {
        SECRET_STORE.updateTreeState(_enclaveAddress);
        secretStorage[_enclaveAddress].storageOccupied -= _secretSize;
    }

    function _removeStoreSecretId(
        address _enclaveAddress,
        uint256 _secretId
    ) internal {
        uint256 len = secretStorage[_enclaveAddress].ackSecretIds.length;
        for (uint256 index = 0; index < len; index++) {
            if(secretStorage[_enclaveAddress].ackSecretIds[index] == _secretId) {
                if(index != len - 1)
                    secretStorage[_enclaveAddress].ackSecretIds[index] = secretStorage[_enclaveAddress].ackSecretIds[len - 1];
                secretStorage[_enclaveAddress].ackSecretIds.pop();
                break;
            }
        }
    }

    function _markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        _slashStore(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        secretStorage[_enclaveAddress].lastAliveTimestamp = _currentCheckTimestamp;
    }

    function _markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) internal {
        _slashStore(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        secretStorage[_enclaveAddress].deadTimestamp = _currentCheckTimestamp;

        _releaseStore(_enclaveAddress, _storageOccupied);
        delete secretStorage[_enclaveAddress].ackSecretIds;
    }

    function _secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _secretSize,
        uint256 _secretId
    ) internal {
        _releaseStore(_enclaveAddress, _secretSize);
        _removeStoreSecretId(_enclaveAddress, _secretId);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function register(
        address _enclaveAddress,
        uint256 _storageCapacity
    ) external onlySecretStore {
        _register(_enclaveAddress, _storageCapacity);
    }

    function selectStores(
        uint8 _env,
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external onlyRole(SECRET_MANAGER_ROLE) returns (SecretManager.SelectedEnclave[] memory) {
        return _selectStores(_env, _noOfNodesToSelect, _sizeLimit);
    }

    function releaseStore(
        address _enclaveAddress,
        uint256 _secretSize
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _releaseStore(_enclaveAddress, _secretSize);
    }

    function markAliveUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _markAliveUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
    }

    function markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _markDeadUpdate(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _storageOccupied, _recipient);
    }

    function secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _secretSize,
        uint256 _secretId
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _secretTerminationUpdate(_enclaveAddress, _secretSize, _secretId);
    }

    function getSecretStoreLastAliveTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStorage[_enclaveAddress].lastAliveTimestamp;
    }

    function getSecretStoreDeadTimestamp(address _enclaveAddress) external view returns (uint256) {
        return secretStorage[_enclaveAddress].deadTimestamp;
    }

    function getStoreAckSecretIds(address _enclaveAddress) external view returns (uint256[] memory) {
        return secretStorage[_enclaveAddress].ackSecretIds;
    }

    function addAckSecretIdToStore(
        address _enclaveAddress,
        uint256 _ackSecretId
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        secretStorage[_enclaveAddress].ackSecretIds.push(_ackSecretId);
    }

    function getSecretStoreStorageData(
        address _enclaveAddress
    ) external view returns (uint256 storageCapacity,uint256 storageOccupied) {
        return (secretStorage[_enclaveAddress].storageCapacity, secretStorage[_enclaveAddress].storageOccupied);
    }

    //---------------------------------- external functions end ----------------------------------//

    //-------------------------------- SecretManagerRole functions end --------------------------------//
}
