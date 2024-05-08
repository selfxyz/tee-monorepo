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
import "./tree/TreeUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";

contract Executors is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, 
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable,
    TreeUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error ExecutorsZeroAddressToken();
    error ExecutorsZeroMinStakeAmount();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _minStakeAmount
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert ExecutorsZeroAddressToken();
        if(_minStakeAmount == 0)
            revert ExecutorsZeroMinStakeAmount();

        TOKEN = _token;
        MIN_STAKE_AMOUNT = _minStakeAmount;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(
        address /*account*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error ExecutorsZeroAddressAdmin();

    function initialize(
        address _admin,
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert ExecutorsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);
        __TreeUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    //-------------------------------- Executor start --------------------------------//

    modifier isValidExecutor(
        address _executor
    ) {
        if(executors[_executor].enclaveKey == address(0))
            revert ExecutorsInvalidExecutor();
        _;
    }

    struct Executor {
        address enclaveKey;
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 stakeAmount;
        bool status;
        bool unstakeStatus;
        uint256 unstakeAmount;
    }

    // executor => Execution node details
    mapping(address => Executor) public executors;

    bytes32 private constant DOMAIN_SEPARATOR = 
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Executors"),
                keccak256("1")
            )
        );
    
    bytes32 private constant REGISTER_TYPEHASH = 
        keccak256("Register(address executor,uint256 jobCapacity)");

    event ExecutorRegistered(
        address indexed executor,
        address indexed enclaveKey
    );

    event ExecutorDeregisterInitiated(address indexed executor);
    
    event ExecutorDeregistered(address indexed executor);

    event ExecutorStakeAdded(
        address indexed executor,
        uint256 addedAmount
    );

    event ExecutorStakeRemoveInitiated(
        address indexed executor,
        uint256 amount
    );

    event ExecutorStakeRemoved(
        address indexed executor,
        uint256 removedAmount
    );

    error ExecutorsInvalidSigner();
    error ExecutorsExecutorAlreadyExists();
    error ExecutorsAlreadyInitiatedDeregister();
    error ExecutorsAlreadyInitiatedUnstake();
    error ExecutorsInvalidAmount();
    error ExecutorsInvalidExecutor();

    //-------------------------------- internal functions start ----------------------------------//

    function _registerExecutor(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _executor
    ) internal {
        if(executors[_executor].enclaveKey != address(0))
            revert ExecutorsExecutorAlreadyExists();

        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveKey = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifySign(_executor, enclaveKey, _jobCapacity, _signature);

        _register(_executor, enclaveKey, _jobCapacity);

        // add node to the tree if min stake amount deposited
        if(_stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(_executor, uint64(_stakeAmount));

        _addStake(_executor, _stakeAmount);
    }

    function _verifySign(
        address _executor,
        address _enclaveKey,
        uint256 _jobCapacity,
        bytes memory _signature
    ) internal pure {
        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _executor,
                _jobCapacity
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveKey)
            revert ExecutorsInvalidSigner();
    }

    function _register(
        address _executor,
        address _enclaveKey,
        uint256 _jobCapacity
    ) internal {
        executors[_executor].enclaveKey = _enclaveKey;
        executors[_executor].jobCapacity = _jobCapacity;
        executors[_executor].status = true;
        
        emit ExecutorRegistered(_executor, _enclaveKey);
    }

    function _deregisterExecutor(
        address _executor
    ) internal {
        if(!executors[_executor].status)
            revert ExecutorsAlreadyInitiatedDeregister();

        executors[_executor].status = false;

        // remove node from the tree
        _deleteIfPresent(_executor);

        if(executors[_executor].activeJobs == 0)
            _completeDeregister(_executor);
        else
            emit ExecutorDeregisterInitiated(_executor);
    }

    function _addExecutorStake(
        uint256 _amount,
        address _executor
    ) internal {
        if(!executors[_executor].status)
            revert ExecutorsAlreadyInitiatedDeregister();
        if(executors[_executor].unstakeStatus)
            revert ExecutorsAlreadyInitiatedUnstake();
        
        uint256 prevStake = executors[_executor].stakeAmount;
        uint256 updatedStake = prevStake + _amount;

        if(updatedStake >= MIN_STAKE_AMOUNT) {
            if(prevStake < MIN_STAKE_AMOUNT)
                _insert_unchecked(_executor, uint64(updatedStake));
            else if(executors[_executor].activeJobs != executors[_executor].jobCapacity)
                _update_unchecked(_executor, uint64(updatedStake));
        }
        
        _addStake(_executor, _amount);
    }

    function _removeExecutorStake(
        uint256 _amount,
        address _executor
    ) internal {
        if(!executors[_executor].status)
            revert ExecutorsAlreadyInitiatedDeregister();
        if(_amount == 0 || _amount > executors[_executor].stakeAmount - executors[_executor].unstakeAmount)
            revert ExecutorsInvalidAmount();

        if(executors[_executor].activeJobs == 0) {
            uint256 updatedStake = executors[_executor].stakeAmount - _amount;
            
            // remove node from tree if stake falls below min level
            if(updatedStake < MIN_STAKE_AMOUNT)
                _deleteIfPresent(_executor);
            // update the value in tree only if the node exists in the tree
            else
                _update_unchecked(_executor, uint64(updatedStake));

            _removeStake(_executor, _amount);
        }
        else {
            executors[_executor].unstakeStatus = true;
            executors[_executor].unstakeAmount += _amount;
            // remove node from tree so it won't be considered for future jobs
            _deleteIfPresent(_executor);
            emit ExecutorStakeRemoveInitiated(_executor, _amount);
        }
        
    }

    function _addStake(
        address _executor,
        uint256 _amount
    ) internal {
        executors[_executor].stakeAmount += _amount;
        // transfer stake
        TOKEN.safeTransferFrom(_executor, address(this), _amount);

        emit ExecutorStakeAdded(_executor, _amount);
    }

    function _removeStake(
        address _executor,
        uint256 _amount
    ) internal {
        executors[_executor].stakeAmount -= _amount;
        // transfer stake
        TOKEN.safeTransfer(_executor, _amount);

        emit ExecutorStakeRemoved(_executor, _amount);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function whitelistEnclaveImage(
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32, bool) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    function registerExecutor(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerExecutor(_attestationSignature, _attestation, _jobCapacity, _signature, _stakeAmount, _msgSender());
    }

    function deregisterExecutor() external isValidExecutor(_msgSender()) {
        _deregisterExecutor(_msgSender());
    }

    function addExecutorStake(
        uint256 _amount
    ) external isValidExecutor(_msgSender()) {
        _addExecutorStake(_amount, _msgSender());
    }

    function removeExecutorStake(
        uint256 _amount
    ) external isValidExecutor(_msgSender()) {
        _removeExecutorStake(_amount, _msgSender());
    }

    function allowOnlyVerified(
        address _enclaveKey,
        address _executor
    ) external view {
        _allowOnlyVerified(_enclaveKey);
        if(_enclaveKey != executors[_executor].enclaveKey)
            revert ExecutorsInvalidSigner();
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- Executor end -----------------------------------------//


    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectExecutors(
        uint256 _noOfNodesToSelect
    ) internal returns (address[] memory selectedNodes) {
        selectedNodes = _selectNodes(_noOfNodesToSelect);
        for (uint256 index = 0; index < selectedNodes.length; index++) {
            address executor = selectedNodes[index];
            executors[executor].activeJobs += 1;
            
            // if jobCapacity reached then delete from the tree so as to not consider this node in new jobs allocation
            if(executors[executor].activeJobs == executors[executor].jobCapacity)
                _deleteIfPresent(executor);
        }
    }

    function _selectNodes(
        uint256 _noOfNodesToSelect
    ) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(randomizer, _noOfNodesToSelect);
        // require(selectedNodes.length != 0, "NO_EXECUTOR_SELECTED");
    }

    function _updateOnSubmitOutput(
        address _executor
    ) internal {
        _postJobUpdate(_executor);
    }

    function _updateOnExecutionTimeoutSlash(
        address _executor,
        bool _hasExecutedJob
    ) internal {
        // TODO: slash executor if failed to perform the job
        if(!_hasExecutedJob) {}

        _postJobUpdate(_executor);
    }

    function _postJobUpdate(
        address _executor
    ) internal {
        // add back the node to the tree as now it can accept a new job
        if(
            executors[_executor].status && 
            !executors[_executor].unstakeStatus && 
            executors[_executor].activeJobs == executors[_executor].jobCapacity &&
            executors[_executor].stakeAmount >= MIN_STAKE_AMOUNT
        )
            _insert_unchecked(_executor, uint64(executors[_executor].stakeAmount));
        
        executors[_executor].activeJobs -= 1;

        // if user has initiated unstake then release tokens only if no jobs are pending
        if(executors[_executor].unstakeStatus && executors[_executor].activeJobs == 0)
            _completeUnstakePostJob(_executor);

        
        // remove node from tree if stake falls below min level
        if(executors[_executor].stakeAmount < MIN_STAKE_AMOUNT)
            _deleteIfPresent(_executor);

        // if user has initiated deregister
        if(!executors[_executor].status && executors[_executor].activeJobs == 0)
            _completeDeregister(_executor);
    }

    function _completeUnstakePostJob(
        address _executor
    ) internal {
        uint256 amount = executors[_executor].stakeAmount < executors[_executor].unstakeAmount ? executors[_executor].stakeAmount : executors[_executor].unstakeAmount;
        executors[_executor].unstakeAmount = 0;
        executors[_executor].unstakeStatus = false;
        
        _removeStake(_executor, amount);

        // update in tree only if the user has not initiated deregistration
        if(executors[_executor].status && executors[_executor].stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(_executor, uint64(executors[_executor].stakeAmount));
    }

    function _completeDeregister(
        address _executor
    ) internal {
        _removeStake(_executor, executors[_executor].stakeAmount);

        _revokeEnclaveKey(executors[_executor].enclaveKey);
        delete executors[_executor];

        emit ExecutorDeregistered(_executor);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectExecutors(
        uint256 _noOfNodesToSelect
    ) external onlyRole(JOBS_ROLE) returns (address[] memory selectedNodes) {
        return _selectExecutors(_noOfNodesToSelect);
    }

    function updateOnSubmitOutput(
        address _executor
    ) external onlyRole(JOBS_ROLE) {
        _updateOnSubmitOutput(_executor);
    }

    function updateOnExecutionTimeoutSlash(
        address _executor,
        bool _hasExecutedJob
    ) external onlyRole(JOBS_ROLE) {
        _updateOnExecutionTimeoutSlash(_executor, _hasExecutedJob);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
