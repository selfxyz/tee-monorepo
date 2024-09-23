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

/**
 * @title SecretStorage Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract SecretStorage is
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
    error SecretStorageZeroAddressStakingToken();
    /// @notice Thrown when the provided ERC20 token address is zero.
    error SecretStorageZeroAddressUsdcToken();
    /// @notice Thrown when the provided minimum stake amount is zero.
    error SecretStorageZeroMinStakeAmount();

    /**
     * @dev Initializes the logic contract without any admins, safeguarding against takeover.
     * @param attestationVerifier The attestation verifier contract.
     * @param maxAge Maximum age for attestations.
     * @param _token The ERC20 token used for staking.
     * @param _minStakeAmount Minimum stake amount required.
     * @param _slashPercentInBips Slashing percentage in basis points.
     * @param _slashMaxBips Maximum basis points for slashing.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _stakingToken,
        IERC20 _usdcToken,
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips,
        uint256 _noOfNodesToSelect,
        uint8 _env,
        uint256 _globalMaxStoreSize,
        uint256 _globalMinStoreDuration,
        uint256 _globalMaxStoreDuration,
        uint256 _acknowledgementTimeout,
        uint256 _markAliveTimeout,
        uint256 _storageFeeRate,
        address _stakingPaymentPool
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert SecretStorageZeroAddressStakingToken();
        if (address(_usdcToken) == address(0)) revert SecretStorageZeroAddressUsdcToken();
        if (_minStakeAmount == 0) revert SecretStorageZeroMinStakeAmount();

        STAKING_TOKEN = _stakingToken;
        USDC_TOKEN = _usdcToken;
        MIN_STAKE_AMOUNT = _minStakeAmount;

        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;
        ENV = _env;

        // TODO: add checks
        GLOBAL_MAX_STORE_SIZE = _globalMaxStoreSize;
        GLOBAL_MIN_STORE_DURATION = _globalMinStoreDuration;
        GLOBAL_MAX_STORE_DURATION = _globalMaxStoreDuration;
        ACKNOWLEDGEMENT_TIMEOUT = _acknowledgementTimeout;
        MARK_ALIVE_TIMEOUT = _markAliveTimeout;
        STORAGE_FEE_RATE = _storageFeeRate;
        STAKING_PAYMENT_POOL = _stakingPaymentPool;
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
    error SecretStorageZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin and enclave images.
     * @param _admin The address of the admin.
     * @param _images Array of enclave images to initialize.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert SecretStorageZeroAddressAdmin();

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
    IERC20 public immutable USDC_TOKEN;

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

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable NO_OF_NODES_TO_SELECT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_STORE_SIZE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MIN_STORE_DURATION;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_STORE_DURATION;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable ACKNOWLEDGEMENT_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MARK_ALIVE_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable STORAGE_FEE_RATE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable STAKING_PAYMENT_POOL;

    /// @notice enclave stake amount will be divided by 10^18 before adding to the tree
    uint256 public constant STAKE_ADJUSTMENT_FACTOR = 1e18;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    //-------------------------------- Enclave storage start --------------------------------//

    modifier isValidEnclaveStoreOwner(address _enclaveAddress, address _owner) {
        if (enclaveStorage[_enclaveAddress].owner != _owner) revert SecretStorageInvalidEnclaveOwner();
        _;
    }

    struct EnclaveStorage {
        uint256 storageCapacity;
        uint256 storageOccupied;
        uint256 stakeAmount;
        address owner;
        bool draining;
    }

    // enclaveAddress => Storage node details
    mapping(address => EnclaveStorage) public enclaveStorage;

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
        keccak256("Acknowledge(uint256 secretId,address owner,uint256 signTimestamp)");

    bytes32 private constant ALIVE_TYPEHASH =
        keccak256("Alive(uint256 secretId,address owner,uint256 signTimestamp)");

    /// @notice Emitted when a new enclave is registered.
    /// @param enclaveAddress The address of the enclave.
    /// @param owner The owner of the enclave.
    /// @param storageCapacity The maximum storage of the enclave(in bytes).
    event EnclaveStoreRegistered(address indexed enclaveAddress, address indexed owner, uint256 storageCapacity);

    /// @notice Emitted when an enclave is deregistered.
    /// @param enclaveAddress The address of the enclave.
    event EnclaveStoreDeregistered(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is drained.
    /// @param enclaveAddress The address of the enclave.
    event EnclaveStoreDrained(address indexed enclaveAddress);

    /// @notice Emitted when an enclave is revived.
    /// @param enclaveAddress The address of the enclave.
    event EnclaveStoreRevived(address indexed enclaveAddress);

    /// @notice Emitted when stake is added to an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param addedAmount The amount of stake added.
    event EnclaveStoreStakeAdded(address indexed enclaveAddress, uint256 addedAmount);

    /// @notice Emitted when stake is removed from an enclave.
    /// @param enclaveAddress The address of the enclave.
    /// @param removedAmount The amount of stake removed.
    event EnclaveStoreStakeRemoved(address indexed enclaveAddress, uint256 removedAmount);

    /// @notice Thrown when the signature timestamp has expired.
    error SecretStorageSignatureTooOld();
    /// @notice Thrown when the signer of the registration data is invalid.
    error SecretStorageInvalidSigner();
    /// @notice Thrown when attempting to register an enclave that already exists.
    error SecretStorageEnclaveAlreadyExists();
    /// @notice Thrown when attempting to drain an enclave that is already draining.
    error SecretStorageEnclaveAlreadyDraining();
    /// @notice Thrown when attempting to revive an enclave that is not draining.
    error SecretStorageEnclaveAlreadyRevived();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that is not draining.
    error SecretStorageEnclaveNotDraining();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that has pending jobs.
    error SecretStorageEnclaveNotEmpty();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error SecretStorageInvalidEnclaveOwner();

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

    function _registerEnclaveStore(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _storageCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _owner
    ) internal {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if (enclaveStorage[enclaveAddress].owner != address(0)) 
            revert SecretStorageEnclaveAlreadyExists();

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
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE) revert SecretStorageSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _storageCapacity, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert SecretStorageInvalidSigner();
    }

    function _register(
        address _enclaveAddress, 
        address _owner, 
        uint256 _storageCapacity
    ) internal {
        enclaveStorage[_enclaveAddress].storageCapacity = _storageCapacity;
        enclaveStorage[_enclaveAddress].owner = _owner;

        emit EnclaveStoreRegistered(_enclaveAddress, _owner, _storageCapacity);
    }

    function _drainEnclaveStore(address _enclaveAddress) internal {
        if (enclaveStorage[_enclaveAddress].draining) revert SecretStorageEnclaveAlreadyDraining();

        enclaveStorage[_enclaveAddress].draining = true;

        // remove node from the tree
        _deleteIfPresent(ENV, _enclaveAddress);

        emit EnclaveStoreDrained(_enclaveAddress);
    }

    function _reviveEnclaveStore(address _enclaveAddress) internal {
        EnclaveStorage memory enclaveStoreNode = enclaveStorage[_enclaveAddress];
        if (!enclaveStoreNode.draining) revert SecretStorageEnclaveAlreadyRevived();

        enclaveStorage[_enclaveAddress].draining = false;

        // insert node in the tree
        if (enclaveStoreNode.stakeAmount >= MIN_STAKE_AMOUNT && enclaveStoreNode.storageOccupied < enclaveStoreNode.storageCapacity) {
            _insert_unchecked(ENV, _enclaveAddress, uint64(enclaveStoreNode.stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }

        emit EnclaveStoreRevived(_enclaveAddress);
    }

    function _deregisterEnclaveStore(address _enclaveAddress) internal {
        if (!enclaveStorage[_enclaveAddress].draining) revert SecretStorageEnclaveNotDraining();
        if (enclaveStorage[_enclaveAddress].storageOccupied != 0) revert SecretStorageEnclaveNotEmpty();

        _removeStake(_enclaveAddress, enclaveStorage[_enclaveAddress].stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete enclaveStorage[_enclaveAddress];

        emit EnclaveStoreDeregistered(_enclaveAddress);
    }

    function _addEnclaveStoreStake(uint256 _amount, address _enclaveAddress) internal {
        EnclaveStorage memory enclaveStoreNode = enclaveStorage[_enclaveAddress];
        uint256 updatedStake = enclaveStoreNode.stakeAmount + _amount;

        if (
            !enclaveStoreNode.draining &&
            enclaveStoreNode.storageOccupied < enclaveStoreNode.storageCapacity &&
            updatedStake >= MIN_STAKE_AMOUNT
        ) {
            // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
            _upsert(ENV, _enclaveAddress, uint64(updatedStake / STAKE_ADJUSTMENT_FACTOR));
        }

        _addStake(_enclaveAddress, _amount);
    }

    function _removeEnclaveStoreStake(uint256 _amount, address _enclaveAddress) internal {
        if (!enclaveStorage[_enclaveAddress].draining) revert SecretStorageEnclaveNotDraining();
        if (enclaveStorage[_enclaveAddress].storageOccupied != 0) revert SecretStorageEnclaveNotEmpty();

        _removeStake(_enclaveAddress, _amount);
    }

    function _addStake(address _enclaveAddress, uint256 _amount) internal {
        enclaveStorage[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        STAKING_TOKEN.safeTransferFrom(enclaveStorage[_enclaveAddress].owner, address(this), _amount);

        emit EnclaveStoreStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(address _enclaveAddress, uint256 _amount) internal {
        enclaveStorage[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        STAKING_TOKEN.safeTransfer(enclaveStorage[_enclaveAddress].owner, _amount);

        emit EnclaveStoreStakeRemoved(_enclaveAddress, _amount);
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
    function registerEnclaveStore(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _storageCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerEnclaveStore(
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
    function deregisterEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress, _msgSender()) {
        _deregisterEnclaveStore(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress, _msgSender()) {
        _drainEnclaveStore(_enclaveAddress);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress, _msgSender()) {
        _reviveEnclaveStore(_enclaveAddress);
    }

    /**
     * @notice Adds stake to an enclave node.
     * @param _enclaveAddress The address of the enclave to add stake to.
     * @param _amount The amount of stake to add.
     * @dev Caller must be the owner of the enclave node.
     */
    function addEnclaveStoreStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidEnclaveStoreOwner(_enclaveAddress, _msgSender()) {
        _addEnclaveStoreStake(_amount, _enclaveAddress);
    }

    /**
     * @notice Removes stake from an enclave node.
     * @param _enclaveAddress The address of the enclave to remove stake from.
     * @param _amount The amount of stake to remove.
     * @dev Caller must be the owner of the enclave node.
     */
    function removeEnclaveStoreStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidEnclaveStoreOwner(_enclaveAddress, _msgSender()) {
        _removeEnclaveStoreStake(_amount, _enclaveAddress);
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- Enclave storage end -----------------------------------------//

    //--------------------------------------- User storage start -----------------------------------------//

    struct SelectedEnclave {
        address enclaveAddress;
        bool hasAcknowledgedStore;
        uint256 lastAliveTimestamp;
    }

    struct UserStorage {
        address owner;
        uint256 sizeLimit;
        uint256 usdcDeposit;
        uint256 startTimestamp;
        uint256 endTimestamp;
        SelectedEnclave[] selectedEnclaves;
    }

    // secretId => user store data
    mapping(uint256 => UserStorage) public userStorage;

    uint256 public secretId;

    event SecretStoreCreated(
        uint256 indexed secretId,
        address indexed owner,
        uint256 sizeLimit,
        uint256 endTimestamp,
        uint256 usdcDeposit
    );

    event EnclaveAcknowledgedStore(
        uint256 indexed secretId,
        address indexed enclaveAddress
    );

    event EnclaveAcknowledgementFailed(
        uint256 indexed secretId
    );

    event EnclaveStoreAlive(
        uint256 indexed secretId,
        address indexed enclaveAddress
    );

    event EnclaveStoreDead(
        uint256 indexed secretId,
        address indexed prevEnclaveAddress,
        address indexed newEnclaveAddress
    );

    event SecretStoreResourceUnavailable(
        uint256 indexed secretId
    );

    event SecretStoreEndTimestampUpdated(
        uint256 indexed secretId,
        uint256 endTimestamp
    );

    event SecretStoreTerminated(
        uint256 indexed secretId
    );

    error SecretStorageInsufficientUsdcDeposit();
    error SecretStorageInvalidSizeLimit();
    error SecretStorageInvalidEndTimestamp();
    error SecretStorageUnavailableResources();
    error SecretStoreAcknowledgementTimeoutPending();
    error SecretStoreAcknowledgedAlready();
    error SecretStoreUnacknowledged();
    error SecretStoreMarkAliveTimeoutPending();
    error SecretStorageEnclaveNotFound();
    error SecretStorageNotUserStoreOwner();
    error SecretStoreInvalidEndTimestamp();
    error SecretStorageAlreadyTerminated();

    //-------------------------------- internal functions start ----------------------------------//

    function _createSecretStore(
        uint256 _sizeLimit,
        uint256 _endTimestamp,
        uint256 _usdcDeposit,
        address _owner
    ) internal {
        if(_sizeLimit == 0 || _sizeLimit > GLOBAL_MAX_STORE_SIZE)
            revert SecretStorageInvalidSizeLimit();

        if ((_endTimestamp < block.timestamp + GLOBAL_MIN_STORE_DURATION) || (_endTimestamp > block.timestamp + GLOBAL_MAX_STORE_DURATION)) 
            revert SecretStorageInvalidEndTimestamp();

        // TODO: how to calculate usdcDeposit
        uint256 minUsdcDeposit = (_endTimestamp - block.timestamp) * _sizeLimit * STORAGE_FEE_RATE;
        if(_usdcDeposit < minUsdcDeposit)
            revert SecretStorageInsufficientUsdcDeposit();

        USDC_TOKEN.safeTransferFrom(_owner, address(this), _usdcDeposit);

        SelectedEnclave[] memory selectedEnclaves = _selectEnclaves(NO_OF_NODES_TO_SELECT, _sizeLimit);
        if (selectedEnclaves.length < NO_OF_NODES_TO_SELECT)
            revert SecretStorageUnavailableResources();

        userStorage[++secretId] = UserStorage({
            owner: _owner,
            sizeLimit: _sizeLimit,
            usdcDeposit: _usdcDeposit,
            startTimestamp: block.timestamp,
            endTimestamp: _endTimestamp,
            selectedEnclaves: selectedEnclaves
        });

        emit SecretStoreCreated(secretId, _owner, _sizeLimit, _endTimestamp, _usdcDeposit);
    }

    function _acknowledgeStore(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature,
        address _owner
    ) internal {
        address enclaveAddress = _verifyAcknowledgementSign(_secretId, _owner, _signTimestamp, _signature);

        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, enclaveAddress);
        userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore = true;

        emit EnclaveAcknowledgedStore(_secretId, enclaveAddress);
    }

    function _verifyAcknowledgementSign(
        uint256 _secretId,
        address _owner,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE)
            revert SecretStorageSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(ACKNOWLEDGE_TYPEHASH, _secretId, _owner, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
    }

    function _getSelectedEnclaveIndex(
        uint256 _secretId,
        address _enclaveAddress
    ) internal view returns (uint256) {
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            if(userStorage[_secretId].selectedEnclaves[index].enclaveAddress == _enclaveAddress)
                return index;
        }
        revert SecretStorageEnclaveNotFound();
    }

    function _acknowledgeStoreFailed(
        uint256 _secretId
    ) internal {
        if(block.timestamp <= userStorage[_secretId].startTimestamp + ACKNOWLEDGEMENT_TIMEOUT)
            revert SecretStoreAcknowledgementTimeoutPending();

        bool ackFailed;
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        for (uint256 index = 0; index < len; index++) {
            if(!userStorage[_secretId].selectedEnclaves[index].hasAcknowledgedStore) {
                ackFailed = true;
                break;
            }
        }

        if(!ackFailed)
            revert SecretStoreAcknowledgedAlready();

        address owner = userStorage[_secretId].owner;
        uint256 usdcDeposit = userStorage[_secretId].usdcDeposit;
        delete userStorage[_secretId];

        USDC_TOKEN.safeTransfer(owner, usdcDeposit);

        emit EnclaveAcknowledgementFailed(_secretId);
    }

    function _markStoreAlive(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature,
        address _owner
    ) internal {
        address enclaveAddress = _verifyStoreAliveSign(_secretId, _owner, _signTimestamp, _signature);

        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, enclaveAddress);
        userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp = block.timestamp;

        emit EnclaveStoreAlive(_secretId, enclaveAddress);
    }

    function _verifyStoreAliveSign(
        uint256 _secretId,
        address _owner,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE)
            revert SecretStorageSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(ALIVE_TYPEHASH, _secretId, _owner, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
    }

    function _markStoreDead(
        uint256 _secretId,
        address _enclaveAddress
    ) internal {
        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, _enclaveAddress);
        if(!userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore)
            revert SecretStoreUnacknowledged();
        
        if(block.timestamp <= userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp + MARK_ALIVE_TIMEOUT)
            revert SecretStoreMarkAliveTimeoutPending();

        SelectedEnclave[] memory selectedEnclaves = _selectEnclaves(1, userStorage[_secretId].sizeLimit);
        if (selectedEnclaves.length == 0) {
            uint256 len = userStorage[_secretId].selectedEnclaves.length;
            if(enclaveIndex != len - 1)
                userStorage[_secretId].selectedEnclaves[enclaveIndex] = userStorage[_secretId].selectedEnclaves[len - 1];
            userStorage[_secretId].selectedEnclaves.pop();

            emit SecretStoreResourceUnavailable(_secretId);
        }
        else {
            userStorage[_secretId].selectedEnclaves[enclaveIndex] = SelectedEnclave({
                enclaveAddress: selectedEnclaves[0].enclaveAddress,
                hasAcknowledgedStore: false,
                lastAliveTimestamp: 0
            });
        }

        // TODO: slash prev enclave(who's recipient)
        _slashEnclave(_enclaveAddress, STAKING_PAYMENT_POOL);
        _releaseEnclave(_enclaveAddress, userStorage[_secretId].sizeLimit);

        emit EnclaveStoreDead(_secretId, _enclaveAddress, selectedEnclaves[0].enclaveAddress);
    }

    function _updateSecretStoreEndTimestamp(
        uint256 _secretId,
        uint256 _endTimestamp,
        uint256 _usdcDeposit
    ) internal {
        if(userStorage[_secretId].owner != _msgSender())
            revert SecretStorageNotUserStoreOwner();

        if(_endTimestamp < block.timestamp)
            revert SecretStorageInvalidEndTimestamp();

        uint256 currentEndTimestamp = userStorage[_secretId].endTimestamp;
        if(block.timestamp > currentEndTimestamp)
            revert SecretStorageAlreadyTerminated();

        if(_endTimestamp > currentEndTimestamp) {
            USDC_TOKEN.safeTransferFrom(_msgSender(), address(this), _usdcDeposit);
            userStorage[_secretId].usdcDeposit += _usdcDeposit;
            
            uint256 addedDuration = _endTimestamp - currentEndTimestamp;
            uint256 minUsdcDeposit = addedDuration * userStorage[_secretId].sizeLimit * STORAGE_FEE_RATE;
            if(_usdcDeposit < minUsdcDeposit)
                revert SecretStorageInsufficientUsdcDeposit();
        }
        else {
            uint256 removedDuration = currentEndTimestamp - _endTimestamp;
            uint256 usdcRefund = removedDuration * userStorage[_secretId].sizeLimit * STORAGE_FEE_RATE;
            
            userStorage[_secretId].usdcDeposit -= usdcRefund;
            USDC_TOKEN.safeTransfer(_msgSender(), usdcRefund);
        }

        userStorage[_secretId].endTimestamp = _endTimestamp;

        emit SecretStoreEndTimestampUpdated(_secretId, _endTimestamp);
    }

    function _terminateSecretStore(
        uint256 _secretId
    ) internal {
        _updateSecretStoreEndTimestamp(_secretId, block.timestamp, 0);

        emit SecretStoreTerminated(_secretId);
    }

    function _selectEnclaves(
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) internal returns (SelectedEnclave[] memory selectedEnclaves) {
        address[] memory selectedNodes = _selectNodes(_noOfNodesToSelect);
        for (uint256 index = 0; index < selectedNodes.length; index++) {
            address enclaveAddress = selectedNodes[index];
            enclaveStorage[enclaveAddress].storageOccupied += _sizeLimit;

            SelectedEnclave memory selectedEnclave;
            selectedEnclave.enclaveAddress = enclaveAddress;
            selectedEnclaves[index] = selectedEnclave;

            // TODO: need to have some buffer space for each enclave
            if (enclaveStorage[enclaveAddress].storageOccupied >= enclaveStorage[enclaveAddress].storageCapacity)
                _deleteIfPresent(ENV, enclaveAddress);
        }
    }

    function _selectNodes(uint256 _noOfNodesToSelect) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(ENV, randomizer, _noOfNodesToSelect);
    }

    function _slashEnclave(address _enclaveAddress, address _recipient) internal returns (uint256) {
        uint256 totalComp = (enclaveStorage[_enclaveAddress].stakeAmount * SLASH_PERCENT_IN_BIPS) / SLASH_MAX_BIPS;
        enclaveStorage[_enclaveAddress].stakeAmount -= totalComp;

        STAKING_TOKEN.safeTransfer(_recipient, totalComp);
        return totalComp;
    }

    function _releaseEnclave(
        address _enclaveAddress,
        uint256 _sizeLimit
    ) internal {
        if (!enclaveStorage[_enclaveAddress].draining) {
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for enclaveStorage in tree if it already exists else add with latest stake
            if (enclaveStorage[_enclaveAddress].stakeAmount >= MIN_STAKE_AMOUNT)
                _upsert(ENV, _enclaveAddress, uint64(enclaveStorage[_enclaveAddress].stakeAmount / STAKE_ADJUSTMENT_FACTOR));
                // remove node from tree if stake falls below min level
            else _deleteIfPresent(ENV, _enclaveAddress);
        }

        enclaveStorage[_enclaveAddress].storageOccupied -= _sizeLimit;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ----------------------------------//

    function createSecretStore(
        uint256 _sizeLimit,
        uint256 _endTimestamp,
        uint256 _usdcDeposit
    ) external {
        _createSecretStore(_sizeLimit, _endTimestamp, _usdcDeposit, _msgSender());
    }

    function acknowledgeStore(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) external {
        _acknowledgeStore(_secretId, _signTimestamp, _signature, _msgSender());
    }

    function acknowledgeStoreFailed(
        uint256 _secretId
    ) external {
        _acknowledgeStoreFailed(_secretId);
    }

    function markStoreAlive(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) external {
        _markStoreAlive(_secretId, _signTimestamp, _signature, _msgSender());
    }

    function markStoreDead(
        uint256 _secretId,
        address _enclaveAddress
    ) external {
        _markStoreDead(_secretId, _enclaveAddress);
    }

    function updateSecretStoreEndTimestamp(
        uint256 _secretId,
        uint256 _endTimestamp,
        uint256 _usdcDeposit
    ) external {
        _updateSecretStoreEndTimestamp(_secretId, _endTimestamp, _usdcDeposit);
    }

    function terminateSecretStore(
        uint256 _secretId
    ) external {
        _terminateSecretStore(_secretId);
    }

    //-------------------------------- external functions end ----------------------------------//

    //----------------------------------- User storage end --------------------------------------//

    //-------------------------------- SecretStorage functions end --------------------------------//
}
