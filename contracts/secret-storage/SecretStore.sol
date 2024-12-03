// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../AttestationAutherUpgradeable.sol";
import "../serverless-v2/tree/TreeMapUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";
import "./SecretManager.sol";

/**
 * @title SecretStore Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract SecretStore is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable,
    TreeMapUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Thrown when the provided ERC20 token address is zero.
    error SecretStoreZeroAddressStakingToken();
    /// @notice Thrown when the provided minimum stake amount is zero.
    error SecretStoreZeroMinStakeAmount();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param attestationVerifier The attestation verifier contract.
     * @param maxAge Maximum age for attestations.
     * @param _token The ERC20 token used for staking.
     * @param _minStakeAmount Minimum stake amount required.
     * @param _slashPercentInBips Slashing percentage in basis points.
     * @param _slashMaxBips Maximum basis points for slashing.
     * @param _env The execution environment supported by secret store enclaves.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _stakingToken,
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips,
        uint8 _env
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert SecretStoreZeroAddressStakingToken();
        if (_minStakeAmount == 0) revert SecretStoreZeroMinStakeAmount();

        STAKING_TOKEN = _stakingToken;
        MIN_STAKE_AMOUNT = _minStakeAmount;

        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
        ENV = _env;
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
    error SecretStoreZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin and enclave images.
     * @param _admin The address of the admin.
     * @param _images Array of enclave images to initialize.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert SecretStoreZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);
        __TreeMapUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _init_tree(ENV);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable STAKING_TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;

    /// @notice an integer in the range 0-10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice expected to be 10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint8 public immutable ENV;

    /// @notice enclave stake amount will be divided by 10^18 before adding to the tree
    uint256 public constant STAKE_ADJUSTMENT_FACTOR = 1e18;

    bytes32 public constant SECRET_MANAGER_ROLE = keccak256("SECRET_MANAGER_ROLE");

    //-------------------------------- SecretStore start --------------------------------//

    modifier isValidSecretStoreOwner(address _enclaveAddress) {
        _isValidSecretStoreOwner(_enclaveAddress);
        _;
    }

    function _isValidSecretStoreOwner(address _enclaveAddress) internal view {
        if (secretStorage[_enclaveAddress].owner != _msgSender())
            revert SecretStoreInvalidEnclaveOwner();
    }

    struct SecretStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 stakeAmount;
        uint256 lastAliveTimestamp;
        uint256 deadTimestamp;
        address owner;
        bool draining;
        uint256[] ackSecretIds;
    }

    // enclaveAddress => Storage node details
    mapping(address => SecretStorage) public secretStorage;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.SecretStore"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256 storageCapacity,uint256 signTimestamp)");

    bytes32 private constant ACKNOWLEDGE_TYPEHASH =
        keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

    bytes32 private constant ALIVE_TYPEHASH =
        keccak256("Alive(uint256 secretId,uint256 signTimestamp)");

    /// @notice Emitted when a new enclave is registered.
    /// @param enclaveAddress The address of the enclave.
    /// @param owner The owner of the enclave.
    /// @param storageCapacity The maximum storage of the enclave(in bytes).
    event SecretStoreRegistered(address indexed enclaveAddress, address indexed owner, uint256 storageCapacity);

    /// @notice Emitted when an enclave is deregistered.
    /// @param enclaveAddress The address of the enclave.
    event SecretStoreDeregistered(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is drained.
    /// @param enclaveAddress The address of the enclave.
    event SecretStoreDrained(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is revived.
    /// @param enclaveAddress The address of the enclave.
    event SecretStoreRevived(address indexed enclaveAddress);

    /// @notice Emitted when stake is added to an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param addedAmount The amount of stake added.
    event SecretStoreStakeAdded(address indexed enclaveAddress, uint256 addedAmount);

    /// @notice Emitted when stake is removed from an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param removedAmount The amount of stake removed.
    event SecretStoreStakeRemoved(address indexed enclaveAddress, uint256 removedAmount);

    /// @notice Thrown when the signature timestamp has expired.
    error SecretStoreSignatureTooOld();
    /// @notice Thrown when the signer of the registration data is invalid.
    error SecretStoreInvalidSigner();
    /// @notice Thrown when attempting to register an enclave that already exists.
    error SecretStoreEnclaveAlreadyExists();
    /// @notice Thrown when attempting to drain an enclave that is already draining.
    error SecretStoreEnclaveAlreadyDraining();
    /// @notice Thrown when attempting to revive an enclave that is not draining.
    error SecretStoreEnclaveAlreadyRevived();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that is not draining.
    error SecretStoreEnclaveNotDraining();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that has pending jobs.
    error SecretStoreEnclaveNotEmpty();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error SecretStoreInvalidEnclaveOwner();

    //-------------------------------- Admin methods start --------------------------------//

    /**
     * @notice Whitelists an enclave image for use by storage enclaves.
     * @param PCR0 The first PCR value.
     * @param PCR1 The second PCR value.
     * @param PCR2 The third PCR value.
     * @return imageId The ID of the whitelisted image.
     * @return success Boolean indicating whether the image was successfully whitelisted.
     */
    function whitelistEnclaveImage(
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32, bool) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    /**
     * @notice Revokes a previously whitelisted enclave image.
     * @param imageId The ID of the image to revoke.
     * @return success Boolean indicating whether the image was successfully revoked.
     */
    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerSecretStore(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _storageCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _owner
    ) internal {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if (secretStorage[enclaveAddress].owner != address(0)) 
            revert SecretStoreEnclaveAlreadyExists();

        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        // signature check
        _verifySign(enclaveAddress, _owner, _storageCapacity, _signTimestamp, _signature);

        _register(enclaveAddress, _owner, _storageCapacity);

        // add node to the tree if min stake amount deposited
        if (_stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(ENV, enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));

        _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifySign(
        address _enclaveAddress,
        address _owner,
        uint256 _storageCapacity,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE)
            revert SecretStoreSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _storageCapacity, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert SecretStoreInvalidSigner();
    }

    function _register(
        address _enclaveAddress, 
        address _owner, 
        uint256 _storageCapacity
    ) internal {
        secretStorage[_enclaveAddress].storageCapacity = _storageCapacity;
        secretStorage[_enclaveAddress].lastAliveTimestamp = block.timestamp;
        secretStorage[_enclaveAddress].owner = _owner;

        emit SecretStoreRegistered(_enclaveAddress, _owner, _storageCapacity);
    }

    function _drainSecretStore(address _enclaveAddress) internal {
        if (secretStorage[_enclaveAddress].draining) revert SecretStoreEnclaveAlreadyDraining();

        secretStorage[_enclaveAddress].draining = true;

        // remove node from the tree
        _deleteIfPresent(ENV, _enclaveAddress);

        emit SecretStoreDrained(_enclaveAddress);
    }

    function _reviveSecretStore(address _enclaveAddress) internal {
        SecretStorage memory secretStoreNode = secretStorage[_enclaveAddress];
        if (!secretStoreNode.draining) revert SecretStoreEnclaveAlreadyRevived();

        secretStorage[_enclaveAddress].draining = false;

        // insert node in the tree
        if (secretStoreNode.stakeAmount >= MIN_STAKE_AMOUNT && secretStoreNode.storageOccupied < secretStoreNode.storageCapacity) {
            _insert_unchecked(ENV, _enclaveAddress, uint64(secretStoreNode.stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }

        emit SecretStoreRevived(_enclaveAddress);
    }

    function _deregisterSecretStore(address _enclaveAddress) internal {
        if (!secretStorage[_enclaveAddress].draining) revert SecretStoreEnclaveNotDraining();
        if (secretStorage[_enclaveAddress].storageOccupied != 0) revert SecretStoreEnclaveNotEmpty();

        _removeStake(_enclaveAddress, secretStorage[_enclaveAddress].stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete secretStorage[_enclaveAddress];

        emit SecretStoreDeregistered(_enclaveAddress);
    }

    function _addSecretStoreStake(uint256 _amount, address _enclaveAddress) internal {
        SecretStorage memory secretStoreNode = secretStorage[_enclaveAddress];
        uint256 updatedStake = secretStoreNode.stakeAmount + _amount;

        if (
            !secretStoreNode.draining &&
            secretStoreNode.storageOccupied < secretStoreNode.storageCapacity &&
            updatedStake >= MIN_STAKE_AMOUNT
        ) {
            // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
            _upsert(ENV, _enclaveAddress, uint64(updatedStake / STAKE_ADJUSTMENT_FACTOR));
        }

        _addStake(_enclaveAddress, _amount);
    }

    function _removeSecretStoreStake(uint256 _amount, address _enclaveAddress) internal {
        if (!secretStorage[_enclaveAddress].draining) revert SecretStoreEnclaveNotDraining();
        if (secretStorage[_enclaveAddress].storageOccupied != 0) revert SecretStoreEnclaveNotEmpty();

        _removeStake(_enclaveAddress, _amount);
    }

    function _addStake(address _enclaveAddress, uint256 _amount) internal {
        secretStorage[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        STAKING_TOKEN.safeTransferFrom(secretStorage[_enclaveAddress].owner, address(this), _amount);

        emit SecretStoreStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(address _enclaveAddress, uint256 _amount) internal {
        secretStorage[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        STAKING_TOKEN.safeTransfer(secretStorage[_enclaveAddress].owner, _amount);

        emit SecretStoreStakeRemoved(_enclaveAddress, _amount);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    /**
     * @notice Registers a new enclave node.
     * @param _attestationSignature The attestation signature for verification.
     * @param _attestation The attestation details.
     * @param _storageCapacity The maximum storage of the enclave (in bytes).
     * @param _signTimestamp The timestamp when the signature was created.
     * @param _signature The signature to verify the registration.
     * @param _stakeAmount The amount of stake to be deposited.
     */
    function registerSecretStore(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _storageCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerSecretStore(
            _attestationSignature,
            _attestation,
            _storageCapacity,
            _signTimestamp,
            _signature,
            _stakeAmount,
            _msgSender()
        );
    }

    /**
     * @notice Deregisters an enclave node.
     * @param _enclaveAddress The address of the enclave to deregister.
     * @dev Caller must be the owner of the enclave node.
     */
    function deregisterSecretStore(address _enclaveAddress) external isValidSecretStoreOwner(_enclaveAddress) {
        _deregisterSecretStore(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainSecretStore(address _enclaveAddress) external isValidSecretStoreOwner(_enclaveAddress) {
        _drainSecretStore(_enclaveAddress);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveSecretStore(address _enclaveAddress) external isValidSecretStoreOwner(_enclaveAddress) {
        _reviveSecretStore(_enclaveAddress);
    }

    /**
     * @notice Adds stake to an enclave node.
     * @param _enclaveAddress The address of the enclave to add stake to.
     * @param _amount The amount of stake to add.
     * @dev Caller must be the owner of the enclave node.
     */
    function addSecretStoreStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidSecretStoreOwner(_enclaveAddress) {
        _addSecretStoreStake(_amount, _enclaveAddress);
    }

    /**
     * @notice Removes stake from an enclave node.
     * @param _enclaveAddress The address of the enclave to remove stake from.
     * @param _amount The amount of stake to remove.
     * @dev Caller must be the owner of the enclave node.
     */
    function removeSecretStoreStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidSecretStoreOwner(_enclaveAddress) {
        _removeSecretStoreStake(_amount, _enclaveAddress);
    }

    /**
     * @notice Allows only verified addresses to perform certain actions.
     * @param _signer The address to be verified.
     */
    function allowOnlyVerified(address _signer) external view {
        _allowOnlyVerified(_signer);
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- SecretStore end -----------------------------------------//

    //----------------------------- SecretManagerRole functions start ---------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectEnclaves(
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) internal returns (SecretManager.SelectedEnclave[] memory) {
        address[] memory selectedNodes = _selectNodes(_noOfNodesToSelect);

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
                _deleteIfPresent(ENV, enclaveAddress);
        }
        return selectedEnclaves;
    }

    function _selectNodes(uint256 _noOfNodesToSelect) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(ENV, randomizer, _noOfNodesToSelect);
    }

    function _slashEnclave(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        address _recipient
    ) internal {
        uint256 lastAliveTimestamp = secretStorage[_enclaveAddress].lastAliveTimestamp;
        uint256 deadTimestamp = secretStorage[_enclaveAddress].deadTimestamp;
        uint256 lastCheckTimestamp = (lastAliveTimestamp > deadTimestamp) ? lastAliveTimestamp : deadTimestamp;
        uint256 missedEpochsCount = (_currentCheckTimestamp - lastCheckTimestamp) / _markAliveTimeout;

        if(missedEpochsCount > 0) {
            uint256 stakeAmount = secretStorage[_enclaveAddress].stakeAmount;
            // compounding slashing formula: remainingStakeAmount = stakeAmount * (1 - (r/100)) ^ n
            uint256 remainingStakeAmount = stakeAmount * ((SLASH_MAX_BIPS - SLASH_PERCENT_IN_BIPS) ** missedEpochsCount) / (SLASH_MAX_BIPS ** missedEpochsCount);
            uint256 slashAmount = stakeAmount - remainingStakeAmount;
            secretStorage[_enclaveAddress].stakeAmount = remainingStakeAmount;

            STAKING_TOKEN.safeTransfer(_recipient, slashAmount);
        }
    }

    function _releaseEnclave(
        address _enclaveAddress,
        uint256 _sizeLimit
    ) internal {
        if (!secretStorage[_enclaveAddress].draining) {
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for secretStorage in tree if it already exists else add with latest stake
            if (secretStorage[_enclaveAddress].stakeAmount >= MIN_STAKE_AMOUNT)
                _upsert(ENV, _enclaveAddress, uint64(secretStorage[_enclaveAddress].stakeAmount / STAKE_ADJUSTMENT_FACTOR));
                // remove node from tree if stake falls below min level
            else _deleteIfPresent(ENV, _enclaveAddress);
        }

        secretStorage[_enclaveAddress].storageOccupied -= _sizeLimit;
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
        _slashEnclave(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        secretStorage[_enclaveAddress].lastAliveTimestamp = _currentCheckTimestamp;
    }

    function _markDeadUpdate(
        address _enclaveAddress,
        uint256 _currentCheckTimestamp,
        uint256 _markAliveTimeout,
        uint256 _storageOccupied,
        address _recipient
    ) internal {
        _slashEnclave(_enclaveAddress, _currentCheckTimestamp, _markAliveTimeout, _recipient);
        secretStorage[_enclaveAddress].deadTimestamp = _currentCheckTimestamp;

        _releaseEnclave(_enclaveAddress, _storageOccupied);
        delete secretStorage[_enclaveAddress].ackSecretIds;
    }

    function _secretTerminationUpdate(
        address _enclaveAddress,
        uint256 _sizeLimit,
        uint256 _secretId
    ) internal {
        _releaseEnclave(_enclaveAddress, _sizeLimit);
        _removeStoreSecretId(_enclaveAddress, _secretId);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectEnclaves(
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external onlyRole(SECRET_MANAGER_ROLE) returns (SecretManager.SelectedEnclave[] memory) {
        return _selectEnclaves(_noOfNodesToSelect, _sizeLimit);
    }

    function releaseEnclave(
        address _enclaveAddress,
        uint256 _sizeLimit
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _releaseEnclave(_enclaveAddress, _sizeLimit);
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
        uint256 _sizeLimit,
        uint256 _secretId
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        _secretTerminationUpdate(_enclaveAddress, _sizeLimit, _secretId);
    }

    function getSecretStoreOwner(address _enclaveAddress) external view returns (address) {
        return secretStorage[_enclaveAddress].owner;
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

    function deleteTreeNodes(
        address[] memory _enclaveAddresses
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        uint256 len = _enclaveAddresses.length;
        for (uint256 index = 0; index < len; index++)
            _deleteIfPresent(ENV, _enclaveAddresses[index]);
    }

    function addTreeNodes(
        address[] memory _enclaveAddresses
    ) external onlyRole(SECRET_MANAGER_ROLE) {
        uint256 len = _enclaveAddresses.length;
        for (uint256 index = 0; index < len; index++)
            _insert_unchecked(ENV, _enclaveAddresses[index], uint64(secretStorage[_enclaveAddresses[index]].stakeAmount / STAKE_ADJUSTMENT_FACTOR));
    }

    function getSecretStoresStake(
        address[] memory _enclaveAddresses
    ) external view returns (uint256[] memory) {
        uint256[] memory stakeAmounts;
        uint256 len = _enclaveAddresses.length;
        for (uint256 index = 0; index < len; index++)
            stakeAmounts[index] = secretStorage[_enclaveAddresses[index]].stakeAmount;

        return stakeAmounts;
    }


    //---------------------------------- external functions end ----------------------------------//

    //-------------------------------- SecretManagerRole functions end --------------------------------//
}
