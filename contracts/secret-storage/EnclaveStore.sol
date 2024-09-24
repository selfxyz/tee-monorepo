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
import "./SecretStore.sol";

/**
 * @title EnclaveStore Contract
 * @notice Manages the registration, staking, and job assignment of execution nodes.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract EnclaveStore is
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
    error EnclaveStoreZeroAddressStakingToken();
    /// @notice Thrown when the provided minimum stake amount is zero.
    error EnclaveStoreZeroMinStakeAmount();

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
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips,
        uint8 _env
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert EnclaveStoreZeroAddressStakingToken();
        if (_minStakeAmount == 0) revert EnclaveStoreZeroMinStakeAmount();

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
    error EnclaveStoreZeroAddressAdmin();

    /**
     * @dev Initializes the contract with the given admin and enclave images.
     * @param _admin The address of the admin.
     * @param _images Array of enclave images to initialize.
     */
    function initialize(address _admin, EnclaveImage[] memory _images) public initializer {
        if (_admin == address(0)) revert EnclaveStoreZeroAddressAdmin();

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

    bytes32 public constant SECRET_STORE_ROLE = keccak256("SECRET_STORE_ROLE");

    //-------------------------------- EnclaveStore start --------------------------------//

    modifier isValidEnclaveStoreOwner(address _enclaveAddress) {
        _isValidEnclaveStoreOwner(_enclaveAddress);
        _;
    }

    function _isValidEnclaveStoreOwner(address _enclaveAddress) internal view {
        if (enclaveStorage[_enclaveAddress].owner != _msgSender())
            revert EnclaveStoreInvalidEnclaveOwner();
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
                keccak256("marlin.oyster.EnclaveStore"),
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
    error EnclaveStoreSignatureTooOld();
    /// @notice Thrown when the signer of the registration data is invalid.
    error EnclaveStoreInvalidSigner();
    /// @notice Thrown when attempting to register an enclave that already exists.
    error EnclaveStoreEnclaveAlreadyExists();
    /// @notice Thrown when attempting to drain an enclave that is already draining.
    error EnclaveStoreEnclaveAlreadyDraining();
    /// @notice Thrown when attempting to revive an enclave that is not draining.
    error EnclaveStoreEnclaveAlreadyRevived();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that is not draining.
    error EnclaveStoreEnclaveNotDraining();
    /// @notice Thrown when attempting to deregister or remove stake from an enclave that has pending jobs.
    error EnclaveStoreEnclaveNotEmpty();
    /// @notice Thrown when the provided enclave owner does not match the stored owner.
    error EnclaveStoreInvalidEnclaveOwner();

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
            revert EnclaveStoreEnclaveAlreadyExists();

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
            revert EnclaveStoreSignatureTooOld();

        bytes32 hashStruct = keccak256(abi.encode(REGISTER_TYPEHASH, _owner, _storageCapacity, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if (signer != _enclaveAddress) revert EnclaveStoreInvalidSigner();
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
        if (enclaveStorage[_enclaveAddress].draining) revert EnclaveStoreEnclaveAlreadyDraining();

        enclaveStorage[_enclaveAddress].draining = true;

        // remove node from the tree
        _deleteIfPresent(ENV, _enclaveAddress);

        emit EnclaveStoreDrained(_enclaveAddress);
    }

    function _reviveEnclaveStore(address _enclaveAddress) internal {
        EnclaveStorage memory enclaveStoreNode = enclaveStorage[_enclaveAddress];
        if (!enclaveStoreNode.draining) revert EnclaveStoreEnclaveAlreadyRevived();

        enclaveStorage[_enclaveAddress].draining = false;

        // insert node in the tree
        if (enclaveStoreNode.stakeAmount >= MIN_STAKE_AMOUNT && enclaveStoreNode.storageOccupied < enclaveStoreNode.storageCapacity) {
            _insert_unchecked(ENV, _enclaveAddress, uint64(enclaveStoreNode.stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }

        emit EnclaveStoreRevived(_enclaveAddress);
    }

    function _deregisterEnclaveStore(address _enclaveAddress) internal {
        if (!enclaveStorage[_enclaveAddress].draining) revert EnclaveStoreEnclaveNotDraining();
        if (enclaveStorage[_enclaveAddress].storageOccupied != 0) revert EnclaveStoreEnclaveNotEmpty();

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
        if (!enclaveStorage[_enclaveAddress].draining) revert EnclaveStoreEnclaveNotDraining();
        if (enclaveStorage[_enclaveAddress].storageOccupied != 0) revert EnclaveStoreEnclaveNotEmpty();

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
    function deregisterEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress) {
        _deregisterEnclaveStore(_enclaveAddress);
    }

    /**
     * @notice Drains an enclave node, making it inactive for new secret stores.
     * @param _enclaveAddress The address of the enclave to drain.
     * @dev Caller must be the owner of the enclave node.
     */
    function drainEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress) {
        _drainEnclaveStore(_enclaveAddress);
    }

    /**
     * @notice Revives a previously drained enclave node.
     * @param _enclaveAddress The address of the enclave to revive.
     * @dev Caller must be the owner of the enclave node.
     */
    function reviveEnclaveStore(address _enclaveAddress) external isValidEnclaveStoreOwner(_enclaveAddress) {
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
    ) external isValidEnclaveStoreOwner(_enclaveAddress) {
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
    ) external isValidEnclaveStoreOwner(_enclaveAddress) {
        _removeEnclaveStoreStake(_amount, _enclaveAddress);
    }

    /**
     * @notice Allows only verified addresses to perform certain actions.
     * @param _signer The address to be verified.
     */
    function allowOnlyVerified(address _signer) external view {
        _allowOnlyVerified(_signer);
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- EnclaveStore end -----------------------------------------//

    //----------------------------- SecretStoreRole functions start ---------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectEnclaves(
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) internal returns (SecretStore.SelectedEnclave[] memory selectedEnclaves) {
        address[] memory selectedNodes = _selectNodes(_noOfNodesToSelect);
        for (uint256 index = 0; index < selectedNodes.length; index++) {
            address enclaveAddress = selectedNodes[index];
            enclaveStorage[enclaveAddress].storageOccupied += _sizeLimit;

            SecretStore.SelectedEnclave memory selectedEnclave;
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

    function _slashEnclave(
        address _enclaveAddress,
        address _recipient
    ) internal returns (uint256) {
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

    //-------------------------------- external functions start ----------------------------------//

    function selectEnclaves(
        uint256 _noOfNodesToSelect,
        uint256 _sizeLimit
    ) external onlyRole(SECRET_STORE_ROLE) returns (SecretStore.SelectedEnclave[] memory selectedEnclaves) {
        return _selectEnclaves(_noOfNodesToSelect, _sizeLimit);
    }

    function slashEnclave(
        address _enclaveAddress,
        address _recipient
    ) external onlyRole(SECRET_STORE_ROLE) returns (uint256) {
        return _slashEnclave(_enclaveAddress, _recipient);
    }

    function releaseEnclave(
        address _enclaveAddress,
        uint256 _sizeLimit
    ) external onlyRole(SECRET_STORE_ROLE) {
        _releaseEnclave(_enclaveAddress, _sizeLimit);
    }

    //---------------------------------- external functions end ----------------------------------//

    //-------------------------------- SecretStoreRole functions end --------------------------------//
}
