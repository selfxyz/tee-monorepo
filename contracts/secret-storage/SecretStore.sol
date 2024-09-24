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
import "./EnclaveStore.sol";

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
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Thrown when the provided ERC20 token address is zero.
    error SecretStoreZeroAddressUsdcToken();

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
        IERC20 _usdcToken,
        uint256 _noOfNodesToSelect,
        uint256 _globalMaxStoreSize,
        uint256 _globalMinStoreDuration,
        uint256 _globalMaxStoreDuration,
        uint256 _acknowledgementTimeout,
        uint256 _markAliveTimeout,
        uint256 _storageFeeRate,
        address _stakingPaymentPool,
        address _storageEnclaves
    ) {
        _disableInitializers();

        if (address(_usdcToken) == address(0)) revert SecretStoreZeroAddressUsdcToken();

        USDC_TOKEN = _usdcToken;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;

        // TODO: add checks
        GLOBAL_MAX_STORE_SIZE = _globalMaxStoreSize;
        GLOBAL_MIN_STORE_DURATION = _globalMinStoreDuration;
        GLOBAL_MAX_STORE_DURATION = _globalMaxStoreDuration;
        ACKNOWLEDGEMENT_TIMEOUT = _acknowledgementTimeout;
        MARK_ALIVE_TIMEOUT = _markAliveTimeout;
        STORAGE_FEE_RATE = _storageFeeRate;
        STAKING_PAYMENT_POOL = _stakingPaymentPool;
        ENCLAVE_STORE = EnclaveStore(_storageEnclaves);
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
     * @dev Initializes the contract with the given admin.
     * @param _admin The address of the admin.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert SecretStoreZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable USDC_TOKEN;

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

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    EnclaveStore public immutable ENCLAVE_STORE;

    //------------------------------------ SecretStore start -----------------------------------//

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.SecretStore"),
                keccak256("1")
            )
        );

    bytes32 private constant ACKNOWLEDGE_TYPEHASH =
        keccak256("Acknowledge(uint256 secretId,uint256 signTimestamp)");

    bytes32 private constant ALIVE_TYPEHASH =
        keccak256("Alive(uint256 secretId,uint256 signTimestamp)");

    /// @notice Thrown when the signature timestamp has expired.
    error SecretStoreSignatureTooOld();

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

    error SecretStoreInsufficientUsdcDeposit();
    error SecretStoreInvalidSizeLimit();
    error SecretStoreInvalidEndTimestamp();
    error SecretStoreUnavailableResources();
    error SecretStoreAcknowledgementTimeOver();
    error SecretStoreAcknowledgementTimeoutPending();
    error SecretStoreAcknowledgedAlready();
    error SecretStoreMarkAliveTimeoutOver();
    error SecretStoreUnacknowledged();
    error SecretStoreEnclaveNotFound();
    error SecretStoreNotUserStoreOwner();
    error SecretStoreAlreadyTerminated();

    //-------------------------------- internal functions start ----------------------------------//

    function _createSecretStore(
        uint256 _sizeLimit,
        uint256 _endTimestamp,
        uint256 _usdcDeposit,
        address _owner
    ) internal {
        if(_sizeLimit == 0 || _sizeLimit > GLOBAL_MAX_STORE_SIZE)
            revert SecretStoreInvalidSizeLimit();

        if ((_endTimestamp < block.timestamp + GLOBAL_MIN_STORE_DURATION) || (_endTimestamp > block.timestamp + GLOBAL_MAX_STORE_DURATION)) 
            revert SecretStoreInvalidEndTimestamp();

        // TODO: how to calculate usdcDeposit
        uint256 minUsdcDeposit = (_endTimestamp - block.timestamp) * _sizeLimit * STORAGE_FEE_RATE;
        _checkUsdcDeposit(_usdcDeposit, minUsdcDeposit);

        USDC_TOKEN.safeTransferFrom(_owner, address(this), _usdcDeposit);

        SelectedEnclave[] memory selectedEnclaves = ENCLAVE_STORE.selectEnclaves(NO_OF_NODES_TO_SELECT, _sizeLimit);
        if (selectedEnclaves.length < NO_OF_NODES_TO_SELECT)
            revert SecretStoreUnavailableResources();

        uint256 id = ++secretId;
        userStorage[id].owner = _owner;
        userStorage[id].sizeLimit = _sizeLimit;
        userStorage[id].usdcDeposit = _usdcDeposit;
        userStorage[id].startTimestamp = block.timestamp;
        userStorage[id].endTimestamp = _endTimestamp;

        // cannot allocate memory array directly to storage var
        for (uint256 index = 0; index < selectedEnclaves.length; index++) {
            userStorage[id].selectedEnclaves.push(selectedEnclaves[index]);
        }

        emit SecretStoreCreated(secretId, _owner, _sizeLimit, _endTimestamp, _usdcDeposit);
    }

    function _checkUsdcDeposit(
        uint256 _usdcDeposit,
        uint256 _minUsdcDeposit
    ) internal pure {
        if(_usdcDeposit < _minUsdcDeposit)
            revert SecretStoreInsufficientUsdcDeposit();
    }

    function _acknowledgeStore(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal {
        if(block.timestamp > userStorage[_secretId].startTimestamp + ACKNOWLEDGEMENT_TIMEOUT)
            revert SecretStoreAcknowledgementTimeOver();

        address enclaveAddress = _verifyAcknowledgementSign(_secretId, _signTimestamp, _signature);

        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, enclaveAddress);
        userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore = true;
        userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp = _signTimestamp;

        emit EnclaveAcknowledgedStore(_secretId, enclaveAddress);
    }

    function _verifyAcknowledgementSign(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        _checkSignValidity(_signTimestamp);

        bytes32 hashStruct = keccak256(abi.encode(ACKNOWLEDGE_TYPEHASH, _secretId, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        ENCLAVE_STORE.allowOnlyVerified(signer);
    }

    function _checkSignValidity(uint256 _signTimestamp) internal view {
        if (block.timestamp > _signTimestamp + ENCLAVE_STORE.ATTESTATION_MAX_AGE())
            revert SecretStoreSignatureTooOld();
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
        revert SecretStoreEnclaveNotFound();
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
        address enclaveAddress = _verifyStoreAliveSign(_secretId, _signTimestamp, _signature);

        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, enclaveAddress);
        if(!userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore)
            revert SecretStoreUnacknowledged();
        if(block.timestamp > userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp + MARK_ALIVE_TIMEOUT)
            revert SecretStoreMarkAliveTimeoutOver();

        uint256 endTime;
        if(block.timestamp > userStorage[_secretId].endTimestamp)
            endTime = userStorage[_secretId].endTimestamp;
        else
            endTime = block.timestamp;

        uint256 usdcPayment = ((endTime - userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp) * userStorage[_secretId].sizeLimit * STORAGE_FEE_RATE) / NO_OF_NODES_TO_SELECT;
        userStorage[_secretId].usdcDeposit -= usdcPayment;
        userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp = _signTimestamp;

        USDC_TOKEN.safeTransfer(_owner, usdcPayment);

        // TODO: delete from selectedNodes array and refund remaining usdc
        if(block.timestamp > userStorage[_secretId].endTimestamp) {
            _removeSelectedEnclave(_secretId, enclaveIndex);
            if(userStorage[_secretId].selectedEnclaves.length == 0)
                _refundExcessDepositAndRemoveStore(_secretId);
        }

        emit EnclaveStoreAlive(_secretId, enclaveAddress);
    }

    function _verifyStoreAliveSign(
        uint256 _secretId,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view returns(address signer) {
        _checkSignValidity(_signTimestamp);

        bytes32 hashStruct = keccak256(abi.encode(ALIVE_TYPEHASH, _secretId, _signTimestamp));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        signer = digest.recover(_signature);

        ENCLAVE_STORE.allowOnlyVerified(signer);
    }

    function _markStoreDead(
        uint256 _secretId
    ) internal {
        for (uint256 index = 0; index < userStorage[_secretId].selectedEnclaves.length; ) {
            bool isArrayLengthReduced = _markEnclaveDead(_secretId, userStorage[_secretId].selectedEnclaves[index].enclaveAddress);
            if(!isArrayLengthReduced)
                ++index;
        }

        // TODO: delete data and refund remaining
        if(block.timestamp > userStorage[_secretId].endTimestamp && userStorage[_secretId].selectedEnclaves.length == 0)
            _refundExcessDepositAndRemoveStore(_secretId);
    }

    function _markEnclaveDead(
        uint256 _secretId,
        address _enclaveAddress
    ) internal returns (bool isArrayLengthReduced) {
        uint256 enclaveIndex = _getSelectedEnclaveIndex(_secretId, _enclaveAddress);
        if(!userStorage[_secretId].selectedEnclaves[enclaveIndex].hasAcknowledgedStore)
            return isArrayLengthReduced;
        
        if(block.timestamp <= userStorage[_secretId].selectedEnclaves[enclaveIndex].lastAliveTimestamp + MARK_ALIVE_TIMEOUT)
            return isArrayLengthReduced;

        if(block.timestamp > userStorage[_secretId].endTimestamp) {
            isArrayLengthReduced = true;
            _removeSelectedEnclave(_secretId, enclaveIndex);
        }
        else {
            SelectedEnclave[] memory selectedEnclaves = ENCLAVE_STORE.selectEnclaves(1, userStorage[_secretId].sizeLimit);
            if (selectedEnclaves.length == 0) {
                isArrayLengthReduced = true;
                _removeSelectedEnclave(_secretId, enclaveIndex);
                emit SecretStoreResourceUnavailable(_secretId);
            }
            else {
                userStorage[_secretId].selectedEnclaves[enclaveIndex] = SelectedEnclave({
                    enclaveAddress: selectedEnclaves[0].enclaveAddress,
                    hasAcknowledgedStore: false,
                    lastAliveTimestamp: 0
                });
            }

            emit EnclaveStoreDead(
                _secretId,
                _enclaveAddress, 
                selectedEnclaves.length != 0 ? selectedEnclaves[0].enclaveAddress : address(0)
            );
        }

        // TODO: slash prev enclave(who's recipient)
        ENCLAVE_STORE.slashEnclave(_enclaveAddress, STAKING_PAYMENT_POOL);
        ENCLAVE_STORE.releaseEnclave(_enclaveAddress, userStorage[_secretId].sizeLimit);
    }

    function _removeSelectedEnclave(
        uint256 _secretId,
        uint256 _index
    ) internal {
        uint256 len = userStorage[_secretId].selectedEnclaves.length;
        if(_index != len - 1)
            userStorage[_secretId].selectedEnclaves[_index] = userStorage[_secretId].selectedEnclaves[len - 1];
        userStorage[_secretId].selectedEnclaves.pop();
    }

    function _refundExcessDepositAndRemoveStore(
        uint256 _secretId
    ) internal {
        address owner = userStorage[_secretId].owner;
        uint256 remainingDeposit = userStorage[_secretId].usdcDeposit;
        delete userStorage[_secretId];
        USDC_TOKEN.safeTransfer(owner, remainingDeposit);
    }

    function _updateSecretStoreEndTimestamp(
        uint256 _secretId,
        uint256 _endTimestamp,
        uint256 _usdcDeposit
    ) internal {
        if(userStorage[_secretId].owner != _msgSender())
            revert SecretStoreNotUserStoreOwner();

        if(_endTimestamp < block.timestamp)
            revert SecretStoreInvalidEndTimestamp();

        uint256 currentEndTimestamp = userStorage[_secretId].endTimestamp;
        if(block.timestamp > currentEndTimestamp)
            revert SecretStoreAlreadyTerminated();

        if(_endTimestamp > currentEndTimestamp) {
            USDC_TOKEN.safeTransferFrom(_msgSender(), address(this), _usdcDeposit);
            userStorage[_secretId].usdcDeposit += _usdcDeposit;
            
            uint256 addedDuration = _endTimestamp - currentEndTimestamp;
            uint256 minUsdcDeposit = addedDuration * userStorage[_secretId].sizeLimit * STORAGE_FEE_RATE;
            _checkUsdcDeposit(_usdcDeposit, minUsdcDeposit);
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
        _acknowledgeStore(_secretId, _signTimestamp, _signature);
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
        uint256 _secretId
    ) external {
        _markStoreDead(_secretId);
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

    //-------------------------------- SecretStore functions end --------------------------------//
}
