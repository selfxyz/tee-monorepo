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
import "./Jobs.sol";
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
    // TODO: add min stake limit and if it falls below that limit then remove from tree
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;
    Jobs public jobs;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    function setJobsContract(Jobs _jobs) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(JOBS_ROLE, (address(jobs)));
        jobs = _jobs;
        _grantRole(JOBS_ROLE, address(_jobs));
    }

    //-------------------------------- Executor start --------------------------------//

    struct Executor {
        address operator;
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 stakeAmount;
        bool status;
        bool unstakeStatus;
        uint256 unstakeAmount;
    }

    // enclaveKey => Execution node details
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
        keccak256("Register(address operator,uint256 jobCapacity)");

    error ExecutorsInvalidExecutorOperator();

    modifier onlyExecutorOperator(bytes memory _enclavePubKey) {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(executors[enclaveKey].operator != _msgSender())
            revert ExecutorsInvalidExecutorOperator();
        _;
    }

    event ExecutorRegistered(
        address indexed enclaveKey,
        address indexed operator
    );

    event ExecutorDeregistered(address indexed enclaveKey);

    event ExecutorStakeAdded(
        address indexed enclaveKey,
        uint256 addedAmount,
        uint256 totalAmount
    );

    event ExecutorStakeRemoveInitiated(
        address indexed enclaveKey,
        uint256 amount
    );

    event ExecutorStakeRemoved(
        address indexed enclaveKey,
        uint256 removedAmount,
        uint256 remainingStakedAmount
    );

    error ExecutorsLessStakeAmount();
    error ExecutorsExecutorAlreadyExists();
    error ExecutorsAlreadyDeregistered();
    error ExecutorsInvalidAmount();

    //-------------------------------- internal functions start ----------------------------------//

    function _registerExecutor(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds,
        uint256 _jobCapacity,
        bytes memory _signature,
        uint256 _stakeAmount
    ) internal {
        if(_stakeAmount < MIN_STAKE_AMOUNT)
            revert ExecutorsLessStakeAmount();

        // attestation verification
        _verifyEnclaveKey(_attestation, IAttestationVerifier.Attestation(_enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds));

        // signature check
        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _msgSender(),
                _jobCapacity
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);

        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _stakeAmount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(executors[enclaveKey].operator != address(0))
            revert ExecutorsExecutorAlreadyExists();
        executors[enclaveKey] = Executor({
            operator: _msgSender(),
            jobCapacity: _jobCapacity,
            activeJobs: 0,
            stakeAmount: _stakeAmount,
            status: true,
            unstakeStatus: false,
            unstakeAmount: 0
        });

        // add node to the tree
        _insert_unchecked(enclaveKey, uint64(_stakeAmount));

        emit ExecutorRegistered(enclaveKey, _msgSender());
    }

    function _deregisterExecutor(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(!executors[enclaveKey].status)
            revert ExecutorsAlreadyDeregistered();

        executors[enclaveKey].status = false;

        if(executors[enclaveKey].activeJobs == 0) {
            // return stake amount
            TOKEN.safeTransfer(_msgSender(), executors[enclaveKey].stakeAmount);
            delete executors[enclaveKey];
            _revokeEnclaveKey(enclaveKey);
        }

        // remove node from the tree
        _deleteIfPresent(enclaveKey);

        emit ExecutorDeregistered(enclaveKey);
    }

    function _addExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        if(_amount == 0)
            revert ExecutorsInvalidAmount();
        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _amount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        executors[enclaveKey].stakeAmount += _amount;

        // update the value in tree only if the node exists in the tree
        if(executors[enclaveKey].activeJobs != executors[enclaveKey].jobCapacity)
            _update_unchecked(enclaveKey, uint64(executors[enclaveKey].stakeAmount));

        emit ExecutorStakeAdded(enclaveKey, _amount, executors[enclaveKey].stakeAmount);
    }

    function _removeExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(_amount == 0 || _amount > executors[enclaveKey].stakeAmount - executors[enclaveKey].unstakeAmount)
            revert ExecutorsInvalidAmount();

        if(executors[enclaveKey].activeJobs == 0) {
            executors[enclaveKey].stakeAmount -= _amount;
            TOKEN.safeTransfer(_msgSender(), _amount);
            
            // remove node from tree if stake falls below min level
            if(executors[enclaveKey].stakeAmount < MIN_STAKE_AMOUNT)
                _deleteIfPresent(enclaveKey);
            // update the value in tree only if the node exists in the tree
            else
                _update_unchecked(enclaveKey, uint64(executors[enclaveKey].stakeAmount));

            emit ExecutorStakeRemoved(enclaveKey, _amount, executors[enclaveKey].stakeAmount);
        }
        else {
            executors[enclaveKey].unstakeStatus = true;
            executors[enclaveKey].unstakeAmount += _amount;
            // remove node from tree so it won't be considered for future jobs
            _deleteIfPresent(enclaveKey);
            emit ExecutorStakeRemoveInitiated(enclaveKey, _amount);
        }
        
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
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds,
        uint256 _jobCapacity,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerExecutor(_attestation, _enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds, _jobCapacity, _signature, _stakeAmount);
    }

    function deregisterExecutor(
        bytes memory _enclavePubKey
    ) external onlyExecutorOperator(_enclavePubKey) {
        _deregisterExecutor(_enclavePubKey);
    }

    function addExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) external onlyExecutorOperator(_enclavePubKey) {
        _addExecutorStake(_enclavePubKey, _amount);
    }

    function removeExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) external onlyExecutorOperator(_enclavePubKey) {
        _removeExecutorStake(_enclavePubKey, _amount);
    }

    function allowOnlyVerified(address _key) external view {
        _allowOnlyVerified(_key);
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
            address executorKey = selectedNodes[index];
            executors[executorKey].activeJobs += 1;
            
            // if jobCapacity reached then delete from the tree so as to not consider this node in new jobs allocation
            if(executors[executorKey].activeJobs == executors[executorKey].jobCapacity)
                _deleteIfPresent(executorKey);
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
        address _executorKey
    ) internal {
        _postJobUpdate(_executorKey);
    }

    function _updateOnExecutionTimeoutSlash(
        address _executorKey,
        bool _hasExecutedJob
    ) internal {
        // TODO: slash executor if failed to perform the job
        if(!_hasExecutedJob) {}

        _postJobUpdate(_executorKey);
    }

    function _postJobUpdate(
        address _executorKey
    ) internal {
        // add back the node to the tree as now it can accept a new job
        if(
            executors[_executorKey].status && 
            !executors[_executorKey].unstakeStatus && 
            executors[_executorKey].activeJobs == executors[_executorKey].jobCapacity &&
            executors[_executorKey].stakeAmount >= MIN_STAKE_AMOUNT
        )
            _insert_unchecked(_executorKey, uint64(executors[_executorKey].stakeAmount));
        
        executors[_executorKey].activeJobs -= 1;

        // if user has initiated unstake then release tokens only if no jobs are pending
        if(executors[_executorKey].unstakeStatus && executors[_executorKey].activeJobs == 0) {
            uint256 amount = executors[_executorKey].stakeAmount < executors[_executorKey].unstakeAmount ? executors[_executorKey].stakeAmount : executors[_executorKey].unstakeAmount;
            executors[_executorKey].stakeAmount -= amount;
            TOKEN.safeTransfer(executors[_executorKey].operator, amount);
            executors[_executorKey].unstakeAmount = 0;
            executors[_executorKey].unstakeStatus = false;
            
            emit ExecutorStakeRemoved(_executorKey, amount, executors[_executorKey].stakeAmount);

            // TODO: unstaking completed event
            // update in tree only if the user has not initiated deregistration
            if(executors[_executorKey].status && executors[_executorKey].stakeAmount >= MIN_STAKE_AMOUNT)
                _update_unchecked(_executorKey, uint64(executors[_executorKey].stakeAmount));
        }
        
        // remove node from tree if stake falls below min level
        if(executors[_executorKey].stakeAmount < MIN_STAKE_AMOUNT)
            _deleteIfPresent(_executorKey);

        // if user has initiated deregister
        if(!executors[_executorKey].status && executors[_executorKey].activeJobs == 0) {
            // return stake amount
            TOKEN.safeTransfer(executors[_executorKey].operator, executors[_executorKey].stakeAmount);
            delete executors[_executorKey];
            _revokeEnclaveKey(_executorKey);
        }
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectExecutors(
        uint256 _noOfNodesToSelect
    ) external onlyRole(JOBS_ROLE) returns (address[] memory selectedNodes) {
        return _selectExecutors(_noOfNodesToSelect);
    }

    // TODO:
    // if unstake is true, activeJob = 0 then insert and release unstake tokens
    // if unstake true, active job > 0, then --activeJob
    function updateOnSubmitOutput(
        address _executorKey
    ) external onlyRole(JOBS_ROLE) {
        _updateOnSubmitOutput(_executorKey);
    }

    function updateOnExecutionTimeoutSlash(
        address _executorKey,
        bool _hasExecutedJob
    ) external onlyRole(JOBS_ROLE) {
        _updateOnExecutionTimeoutSlash(_executorKey, _hasExecutedJob);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
