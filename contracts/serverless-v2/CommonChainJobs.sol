// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./CommonChainExecutors.sol";
import "./CommonChainGateways.sol";

contract CommonChainJobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, 
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error ZeroAddressToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IERC20 _token,
        uint256 _relayBufferTime,
        uint256 _executionBufferTime,
        uint256 _noOfNodesToSelect
    ) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert ZeroAddressToken();
        TOKEN = _token;
        RELAY_BUFFER_TIME = _relayBufferTime;
        EXECUTION_BUFFER_TIME = _executionBufferTime;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;
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

    function __CommonChainJobs_init(
        address _admin,
        CommonChainGateways _gateways,
        CommonChainExecutors _executors
    ) public initializer {
        if(_admin == address(0))
            revert ZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        gateways = _gateways;
        executors = _executors;
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    CommonChainGateways public gateways;
    CommonChainExecutors public executors;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable RELAY_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable NO_OF_NODES_TO_SELECT;

    function setGatewaysContract(CommonChainGateways _gateways) external onlyRole(DEFAULT_ADMIN_ROLE) {
        gateways = _gateways;
    }

    function setExecutorsContract(CommonChainExecutors _executors) external onlyRole(DEFAULT_ADMIN_ROLE) {
        executors = _executors;
    }

    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 jobId;
        uint256 deadline;
        uint256 execStartTime;
        address jobOwner;
        uint8 outputCount;
        uint8 sequenceId;
        bool isResourceUnavailable;
    }

    // jobKey => Job
    mapping(uint256 => Job) public jobs;

    // jobKey => executors
    mapping(uint256 => address[]) public selectedExecutors;
    // jobKey => selectedExecutorAddress => hasExecuted
    mapping(uint256 => mapping(address => bool)) public hasExecutedJob;

    event JobRelayed(
        uint256 indexed jobId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 deadline,
        address jobOwner,
        address gatewayOperator,
        address[] selectedExecutors
    );

    event JobResponded(
        uint256 indexed jobId,
        bytes output,
        uint256 totalTime,
        uint8 errorCode,
        uint8 outputCount
    );

    event JobResourceUnavailable(
        uint256 indexed jobId,
        address indexed gatewayOperator
    );

    error RelayTimeOver();
    error JobMarkedEndedAsResourceUnavailable();
    error InvalidSequenceId();
    error JobAlreadyRelayed();
    error UnsupportedChain();
    error ExecutionTimeOver();
    error NotSelectedExecutor();
    error ExecutorAlreadySubmittedOutput();

    //-------------------------------- internal functions start --------------------------------//

    function _relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner
    ) internal {
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert RelayTimeOver();
        if(jobs[_jobId].isResourceUnavailable)
            revert JobMarkedEndedAsResourceUnavailable();
        if(_sequenceId != jobs[_jobId].sequenceId + 1)
            revert InvalidSequenceId();
        if(jobs[_jobId].execStartTime != 0)
            revert JobAlreadyRelayed();
        
        // first 64 bits represent chainId
        uint256 reqChainId = _jobId >> 192;
        if(!gateways.isChainSupported(reqChainId))
            revert UnsupportedChain();

        // signature check
        bytes32 digest = keccak256(
            abi.encodePacked(
                _jobId,
                _codehash,
                _codeInputs,
                _deadline,
                _jobRequestTimestamp,
                _sequenceId,
                _jobOwner
            )
        );
        address signer = digest.recover(_signature);

        gateways.allowOnlyVerified(signer);

        address[] memory selectedNodes = executors.selectExecutors(NO_OF_NODES_TO_SELECT);
        // if no executors are selected, then mark isRosourceAvailable flag of the job and exit
        if(selectedNodes.length < NO_OF_NODES_TO_SELECT) {
            jobs[_jobId].isResourceUnavailable = true;
            emit JobResourceUnavailable(_jobId, _msgSender());
            return;
        }
        selectedExecutors[_jobId] = selectedNodes;

        jobs[_jobId] = Job({
            jobId: _jobId,
            deadline: _deadline,
            execStartTime: block.timestamp,
            jobOwner: _jobOwner,
            outputCount: 0,
            sequenceId: _sequenceId,
            isResourceUnavailable: false
        });

        emit JobRelayed(_jobId, _codehash, _codeInputs, _deadline, _jobOwner, _msgSender(), selectedNodes);
    }

    function _submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) internal {
        if(block.timestamp > jobs[_jobId].execStartTime + jobs[_jobId].deadline + EXECUTION_BUFFER_TIME)
            revert ExecutionTimeOver();

        // signature check
        bytes32 digest = keccak256(
            abi.encodePacked(_jobId, _output, _totalTime, _errorCode)
        );
        address signer = digest.recover(_signature);

        executors.allowOnlyVerified(signer);

        if(!isJobExecutor(_jobId, signer))
            revert NotSelectedExecutor();
        if(hasExecutedJob[_jobId][signer])
            revert ExecutorAlreadySubmittedOutput();

        executors.updateOnSubmitOutput(signer);
        hasExecutedJob[_jobId][signer] = true;

        // TODO: emit executorKey(signer) also if reqd
        emit JobResponded(_jobId, _output, _totalTime, _errorCode, ++jobs[_jobId].outputCount);

        // cleanup job after 3rd output submitted

        // on reward distribution, 1st output executor node gets max reward
        // reward ratio - 2:1:0
    }

    function _isJobExecutor(
        uint256 _jobId,
        address _executor
    ) internal view returns (bool) {
        address[] memory selectedNodes = selectedExecutors[_jobId];
        uint256 len = selectedExecutors[_jobId].length;
        for (uint256 index = 0; index < len; index++) {
            if(selectedNodes[index] == _executor)
                return true;
        }
        return false;
    }

    //-------------------------------- internal functions end ----------------------------------//


    //-------------------------------- external functions start --------------------------------//

    function relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner
    ) external {
        _relayJob(_signature, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner);
    }

    function submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) external {
        _submitOutput(_signature, _jobId, _output, _totalTime, _errorCode);
    }

    function isJobExecutor(
        uint256 _jobId,
        address _executor
    ) public view returns (bool) {
        return _isJobExecutor(_jobId, _executor);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Job end --------------------------------//


    //-------------------------------- Timeout start --------------------------------//

    event SlashedOnExecutionTimeout(
        uint256 indexed jobId,
        address indexed executor
    );

    event GatewayReassigned(
        uint256 indexed jobId,
        address prevGatewayKey,
        address reporterGateway,
        uint8 sequenceId
    );

    error InvalidJob();
    error DeadlineNotOver();

    //-------------------------------- internal functions start ----------------------------------//

    // TODO: active jobs cannot be updated if deadlineover and 2 of the executor nodes haven't submitted response
    function _slashOnExecutionTimeout(
        uint256 _jobId
    ) internal {
        if(jobs[_jobId].jobId == 0)
            revert InvalidJob();

        // check for time
        if(block.timestamp <= jobs[_jobId].execStartTime + jobs[_jobId].deadline + EXECUTION_BUFFER_TIME)
            revert DeadlineNotOver();

        delete jobs[_jobId];

        // slash Execution node

        uint256 len = selectedExecutors[_jobId].length;
        for (uint256 index = 0; index < len; index++) {
            address executorKey = selectedExecutors[_jobId][index];
            executors.updateOnExecutionTimeoutSlash(executorKey, hasExecutedJob[_jobId][executorKey]);
            if(!hasExecutedJob[_jobId][executorKey])
                emit SlashedOnExecutionTimeout(_jobId, executorKey);
            delete hasExecutedJob[_jobId][executorKey];
        }


        delete selectedExecutors[_jobId];
    }

    function _reassignGatewayRelay(
        address _gatewayKeyOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp
    ) internal {
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected
        // TODO: add _jobRequestTimestamp in sign to prevent replay attack
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert RelayTimeOver();

        if(jobs[_jobId].isResourceUnavailable)
            revert JobMarkedEndedAsResourceUnavailable();
        if(_sequenceId != jobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert InvalidSequenceId();
        jobs[_jobId].sequenceId = _sequenceId;

        // signature check
        bytes32 digest = keccak256(abi.encodePacked(_jobId, _gatewayKeyOld, _sequenceId, _jobRequestTimestamp));
        address signer = digest.recover(_signature);

        gateways.allowOnlyVerified(signer);

        emit GatewayReassigned(_jobId, _gatewayKeyOld, _msgSender(), _sequenceId);

        // slash old gateway
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function slashOnExecutionTimeout(
        uint256 _jobId
    ) external {
        _slashOnExecutionTimeout(_jobId);
    }

    function reassignGatewayRelay(
        address _gatewayKeyOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp
    ) external {
        _reassignGatewayRelay(_gatewayKeyOld, _jobId, _signature, _sequenceId, _jobRequestTimestamp);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Timeout end --------------------------------//

    function getSelectedExecutors(
        uint256 _jobId
    ) external view returns (address[] memory) {
        return selectedExecutors[_jobId];
    }
}