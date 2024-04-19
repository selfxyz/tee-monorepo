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
import "./CommonChainJobs.sol";
import "../interfaces/IAttestationVerifier.sol";

contract CommonChainExecutors is
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

    error ZeroAddressToken();
    error InvalidJobContract();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert ZeroAddressToken();
        TOKEN = _token;
    }

    modifier onlyJobsContract() {
        if(_msgSender() != address(jobs))
            revert InvalidJobContract();
        _;
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

    error ZeroAddressAdmin();

    function __CommonChainExecutors_init(
        address _admin,
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert ZeroAddressAdmin();

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
    CommonChainJobs public jobs;

    function setJobsContract(CommonChainJobs _jobs) external onlyRole(DEFAULT_ADMIN_ROLE) {
        jobs = _jobs;
    }

    //-------------------------------- Executor start --------------------------------//

    struct Executor {
        address operator;
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 stakeAmount;
        bool status;
    }

    // enclaveKey => Execution node details
    mapping(address => Executor) public executors;

    error InvalidExecutorOperator();

    modifier onlyExecutorOperator(bytes memory _enclavePubKey) {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(executors[enclaveKey].operator != _msgSender())
            revert InvalidExecutorOperator();
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

    event ExecutorStakeRemoved(
        address indexed enclaveKey,
        uint256 removedAmount,
        uint256 totalAmount
    );

    error ExecutorAlreadyExists();
    error InvalidEnclaveKey();
    error AlreadyDeregistered();

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
        // attestation verification
        _verifyEnclaveKey(_attestation, IAttestationVerifier.Attestation(_enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds));

        // signature check
        bytes32 digest = keccak256(abi.encodePacked(_jobCapacity));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);

        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _stakeAmount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(executors[enclaveKey].operator != address(0))
            revert ExecutorAlreadyExists();
        executors[enclaveKey] = Executor({
            operator: _msgSender(),
            jobCapacity: _jobCapacity,
            activeJobs: 0,
            stakeAmount: _stakeAmount,
            status: true
        });

        // add node to the tree
        _insert_unchecked(enclaveKey, uint64(_stakeAmount));

        emit ExecutorRegistered(enclaveKey, _msgSender());
    } 

    function _deregisterExecutor(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(executors[enclaveKey].operator == address(0))
            revert InvalidEnclaveKey();
        if(!executors[enclaveKey].status)
            revert AlreadyDeregistered();

        executors[enclaveKey].status = false;

        if(executors[enclaveKey].activeJobs == 0) {
            delete executors[enclaveKey];
            _revokeEnclaveKey(_enclavePubKey);
        }

        // remove node from the tree
        _deleteIfPresent(enclaveKey);

        emit ExecutorDeregistered(enclaveKey);

        // return stake amount
    } 

    function _addExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _amount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        executors[enclaveKey].stakeAmount += _amount;

        // update the value in tree only if the node exists in the tree
        if(executors[enclaveKey].activeJobs != executors[enclaveKey].jobCapacity)
            _update_unchecked(enclaveKey, uint64(_amount));

        emit ExecutorStakeAdded(enclaveKey, _amount, executors[enclaveKey].stakeAmount);
    }  

    function _removeExecutorStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        // transfer stake
        TOKEN.safeTransfer(_msgSender(), _amount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        executors[enclaveKey].stakeAmount -= _amount;

        // update the value in tree only if the node exists in the tree
        if(executors[enclaveKey].activeJobs != executors[enclaveKey].jobCapacity)
            _update_unchecked(enclaveKey, uint64(_amount));

        emit ExecutorStakeRemoved(enclaveKey, _amount, executors[enclaveKey].stakeAmount);
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
        // add back the node to the tree as now it can accept a new job
        if(executors[_executorKey].status && executors[_executorKey].activeJobs == executors[_executorKey].jobCapacity)
            _insert_unchecked(_executorKey, uint64(executors[_executorKey].stakeAmount));

        executors[_executorKey].activeJobs -= 1;

        if(!executors[_executorKey].status && executors[_executorKey].activeJobs == 0) {
            delete executors[_executorKey];
            _revokeEnclaveKey(_executorKey);
        }
    }

    function _updateOnExecutionTimeoutSlash(
        address _executorKey
    ) internal {
        // add back the node to the tree as now it can accept a new job
        if(executors[_executorKey].status && executors[_executorKey].activeJobs == executors[_executorKey].jobCapacity)
            _insert_unchecked(_executorKey, uint64(executors[_executorKey].stakeAmount));
        
        executors[_executorKey].activeJobs -= 1;

        // TODO: manage payment and slashing before deleting the executor
        if(!executors[_executorKey].status && executors[_executorKey].activeJobs == 0) {
            delete executors[_executorKey];
            _revokeEnclaveKey(_executorKey);
        }
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectExecutors(
        uint256 _noOfNodesToSelect
    ) external onlyJobsContract returns (address[] memory selectedNodes) {
        return _selectExecutors(_noOfNodesToSelect);
    }

    // TODO:
    // if unstake is true, activeJob = 0 then insert and release unstake tokens
    // if unstake true, active job > 0, then --activeJob
    function updateOnSubmitOutput(
        address _executorKey
    ) external onlyJobsContract {
        _updateOnSubmitOutput(_executorKey);
    }

    function updateOnExecutionTimeoutSlash(
        address _executorKey
    ) external onlyJobsContract {
        _updateOnExecutionTimeoutSlash(_executorKey);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
