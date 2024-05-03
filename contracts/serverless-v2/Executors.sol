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
        address enclaveKey;
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 stakeAmount;
        bool status;
        bool unstakeStatus;
        uint256 unstakeAmount;
    }

    // operator => Execution node details
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

    event ExecutorRegistered(
        address indexed operator,
        address indexed enclaveKey
    );

    event ExecutorDeregistered(address indexed operator);

    event ExecutorStakeAdded(
        address indexed operator,
        uint256 addedAmount,
        uint256 totalAmount
    );

    event ExecutorStakeRemoveInitiated(
        address indexed operator,
        uint256 amount
    );

    event ExecutorStakeRemoved(
        address indexed operator,
        uint256 removedAmount,
        uint256 remainingStakedAmount
    );

    error ExecutorsLessStakeAmount();
    error ExecutorsInvalidSigner();
    error ExecutorsExecutorAlreadyExists();
    error ExecutorsAlreadyDeregistered();
    error ExecutorsInvalidAmount();
    error ExecutorsInvalidExecutor();

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

        address operator = _msgSender();
        // signature check
        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                operator,
                _jobCapacity
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(signer != enclaveKey)
            revert ExecutorsInvalidSigner();

        // transfer stake
        TOKEN.safeTransferFrom(operator, address(this), _stakeAmount);

        if(executors[operator].enclaveKey != address(0))
            revert ExecutorsExecutorAlreadyExists();
        executors[operator] = Executor({
            enclaveKey: enclaveKey,
            jobCapacity: _jobCapacity,
            activeJobs: 0,
            stakeAmount: _stakeAmount,
            status: true,
            unstakeStatus: false,
            unstakeAmount: 0
        });

        // add node to the tree
        _insert_unchecked(operator, uint64(_stakeAmount));

        emit ExecutorRegistered(operator, enclaveKey);
    }

    function _deregisterExecutor() internal {
        address operator = _msgSender();
        _isValidExecutor(operator);
        if(!executors[operator].status)
            revert ExecutorsAlreadyDeregistered();

        executors[operator].status = false;

        if(executors[operator].activeJobs == 0) {
            // return stake amount
            TOKEN.safeTransfer(operator, executors[operator].stakeAmount);
            _revokeEnclaveKey(executors[operator].enclaveKey);
            delete executors[operator];
        }

        // remove node from the tree
        _deleteIfPresent(operator);

        emit ExecutorDeregistered(operator);
    }

    function _addExecutorStake(
        uint256 _amount
    ) internal {
        if(_amount == 0)
            revert ExecutorsInvalidAmount();
        
        address operator = _msgSender();
        _isValidExecutor(operator);
        // transfer stake
        TOKEN.safeTransferFrom(operator, address(this), _amount);
        executors[operator].stakeAmount += _amount;

        // update the value in tree only if the node exists in the tree
        if(executors[operator].activeJobs != executors[operator].jobCapacity)
            _update_unchecked(operator, uint64(executors[operator].stakeAmount));

        emit ExecutorStakeAdded(operator, _amount, executors[operator].stakeAmount);
    }

    function _removeExecutorStake(
        uint256 _amount
    ) internal {
        address operator = _msgSender();
        _isValidExecutor(operator);
        if(_amount == 0 || _amount > executors[operator].stakeAmount - executors[operator].unstakeAmount)
            revert ExecutorsInvalidAmount();

        if(executors[operator].activeJobs == 0) {
            executors[operator].stakeAmount -= _amount;
            TOKEN.safeTransfer(operator, _amount);
            
            // remove node from tree if stake falls below min level
            if(executors[operator].stakeAmount < MIN_STAKE_AMOUNT)
                _deleteIfPresent(operator);
            // update the value in tree only if the node exists in the tree
            else
                _update_unchecked(operator, uint64(executors[operator].stakeAmount));

            emit ExecutorStakeRemoved(operator, _amount, executors[operator].stakeAmount);
        }
        else {
            executors[operator].unstakeStatus = true;
            executors[operator].unstakeAmount += _amount;
            // remove node from tree so it won't be considered for future jobs
            _deleteIfPresent(operator);
            emit ExecutorStakeRemoveInitiated(operator, _amount);
        }
        
    }

    function _isValidExecutor(
        address _operator
    ) internal view {
        if(executors[_operator].enclaveKey == address(0))
            revert ExecutorsInvalidExecutor();
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

    function deregisterExecutor() external {
        _deregisterExecutor();
    }

    function addExecutorStake(
        uint256 _amount
    ) external {
        _addExecutorStake(_amount);
    }

    function removeExecutorStake(
        uint256 _amount
    ) external {
        _removeExecutorStake(_amount);
    }

    function allowOnlyVerified(
        address _enclaveKey,
        address _operator
    ) external view {
        _allowOnlyVerified(_enclaveKey);
        if(_enclaveKey != executors[_operator].enclaveKey)
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
            address operator = selectedNodes[index];
            executors[operator].activeJobs += 1;
            
            // if jobCapacity reached then delete from the tree so as to not consider this node in new jobs allocation
            if(executors[operator].activeJobs == executors[operator].jobCapacity)
                _deleteIfPresent(operator);
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
        address _operator
    ) internal {
        _postJobUpdate(_operator);
    }

    function _updateOnExecutionTimeoutSlash(
        address _operator,
        bool _hasExecutedJob
    ) internal {
        // TODO: slash executor if failed to perform the job
        if(!_hasExecutedJob) {}

        _postJobUpdate(_operator);
    }

    function _postJobUpdate(
        address _operator
    ) internal {
        // add back the node to the tree as now it can accept a new job
        if(
            executors[_operator].status && 
            !executors[_operator].unstakeStatus && 
            executors[_operator].activeJobs == executors[_operator].jobCapacity &&
            executors[_operator].stakeAmount >= MIN_STAKE_AMOUNT
        )
            _insert_unchecked(_operator, uint64(executors[_operator].stakeAmount));
        
        executors[_operator].activeJobs -= 1;

        // if user has initiated unstake then release tokens only if no jobs are pending
        if(executors[_operator].unstakeStatus && executors[_operator].activeJobs == 0) {
            uint256 amount = executors[_operator].stakeAmount < executors[_operator].unstakeAmount ? executors[_operator].stakeAmount : executors[_operator].unstakeAmount;
            executors[_operator].stakeAmount -= amount;
            TOKEN.safeTransfer(_operator, amount);
            executors[_operator].unstakeAmount = 0;
            executors[_operator].unstakeStatus = false;
            
            emit ExecutorStakeRemoved(_operator, amount, executors[_operator].stakeAmount);

            // update in tree only if the user has not initiated deregistration
            if(executors[_operator].status && executors[_operator].stakeAmount >= MIN_STAKE_AMOUNT)
                _update_unchecked(_operator, uint64(executors[_operator].stakeAmount));
        }
        
        // remove node from tree if stake falls below min level
        if(executors[_operator].stakeAmount < MIN_STAKE_AMOUNT)
            _deleteIfPresent(_operator);

        // if user has initiated deregister
        if(!executors[_operator].status && executors[_operator].activeJobs == 0) {
            // return stake amount
            TOKEN.safeTransfer(_operator, executors[_operator].stakeAmount);
            _revokeEnclaveKey(executors[_operator].enclaveKey);
            delete executors[_operator];
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
        address _operator
    ) external onlyRole(JOBS_ROLE) {
        _updateOnSubmitOutput(_operator);
    }

    function updateOnExecutionTimeoutSlash(
        address _operator,
        bool _hasExecutedJob
    ) external onlyRole(JOBS_ROLE) {
        _updateOnExecutionTimeoutSlash(_operator, _hasExecutedJob);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
