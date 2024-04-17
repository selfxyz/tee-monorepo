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
    ) initializer {
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
        uint256 reqChainId;
        bytes32 codehash;
        bytes codeInputs;
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
        uint256 indexed reqChainId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 deadline,
        address jobOwner,
        address gatewayOperator,
        address[] selectedExecutors
    );

    event JobResponded(
        uint256 indexed jobId,
        uint256 indexed reqChainId,
        bytes output,
        uint256 totalTime,
        uint8 errorCode,
        uint8 outputCount
    );

    event JobResourceUnavailable(
        uint256 indexed jobId,
        uint256 indexed reqChainId,
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

    function getKey(
        uint256 _jobId,
        uint256 _reqChainId
    ) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(_jobId, "-", _reqChainId)));
    }

    function relayJob(
        bytes memory _signature,
        uint256 _jobId,
        uint256 _reqChainId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner
    ) external {
        uint256 key = getKey(_jobId, _reqChainId);
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert RelayTimeOver();
        if(jobs[key].isResourceUnavailable)
            revert JobMarkedEndedAsResourceUnavailable();
        if(_sequenceId != jobs[key].sequenceId + 1)
            revert InvalidSequenceId();
        if(jobs[key].execStartTime != 0)
            revert JobAlreadyRelayed();
        if(!gateways.isChainSupported(_reqChainId))
            revert UnsupportedChain();

        // signature check
        bytes32 digest = keccak256(
            abi.encodePacked(
                _jobId,
                _reqChainId,
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
            jobs[key].isResourceUnavailable = true;
            emit JobResourceUnavailable(_jobId, _reqChainId, _msgSender());
            return;
        }
        selectedExecutors[key] = selectedNodes;

        jobs[key] = Job({
            jobId: _jobId,
            reqChainId: _reqChainId,
            codehash: _codehash,
            codeInputs: _codeInputs,
            deadline: _deadline,
            execStartTime: block.timestamp,
            jobOwner: _jobOwner,
            outputCount: 0,
            sequenceId: _sequenceId,
            isResourceUnavailable: false
        });

        emit JobRelayed(_jobId, _reqChainId, _codehash, _codeInputs, _deadline, _jobOwner, _msgSender(), selectedNodes);
    }

    function submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        uint256 _reqChainId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) external {
        uint256 key = getKey(_jobId, _reqChainId);
        if(block.timestamp > jobs[key].execStartTime + jobs[key].deadline + EXECUTION_BUFFER_TIME)
            revert ExecutionTimeOver();

        // signature check
        bytes32 digest = keccak256(
            abi.encodePacked(_jobId, _reqChainId, _output, _totalTime, _errorCode)
        );
        address signer = digest.recover(_signature);

        executors.allowOnlyVerified(signer);

        if(!isJobExecutor(_jobId, _reqChainId, signer))
            revert NotSelectedExecutor();
        if(hasExecutedJob[key][signer])
            revert ExecutorAlreadySubmittedOutput();

        executors.updateOnSubmitOutput(signer);
        hasExecutedJob[key][signer] = true;

        // TODO: emit executorKey(signer) also if reqd
        emit JobResponded(_jobId, _reqChainId, _output, _totalTime, _errorCode, ++jobs[key].outputCount);

        // cleanup job after 3rd output submitted

        // on reward distribution, 1st output executor node gets max reward
        // reward ratio - 2:1:0
    }

    function isJobExecutor(
        uint256 _jobId,
        uint256 _reqChainId,
        address _executor
    ) public view returns (bool) {
        uint256 key = getKey(_jobId, _reqChainId);
        address[] memory selectedNodes = selectedExecutors[key];
        uint256 len = selectedExecutors[key].length;
        for (uint256 index = 0; index < len; index++) {
            if(selectedNodes[index] == _executor)
                return true;
        }
        return false;
    }

    //-------------------------------- Job end --------------------------------//

    //-------------------------------- Timeout start --------------------------------//

    event SlashedOnExecutionTimeout(
        uint256 indexed jobId,
        uint256 indexed reqChainId,
        address[] executors
    );

    event GatewayReassigned(
        uint256 indexed jobId,
        uint256 indexed reqChainId,
        address prevGatewayKey,
        address reporterGateway,
        uint8 sequenceId
    );

    error InvalidJob();
    error DeadlineNotOver();
    error JobAlreadyExecuted();

    function slashOnExecutionTimeout(
        uint256 _jobId,
        uint256 _reqChainId
    ) external {
        uint256 key = getKey(_jobId, _reqChainId);
        if(jobs[key].jobId == 0)
            revert InvalidJob();

        // check for time
        if(block.timestamp <= jobs[key].execStartTime + jobs[key].deadline + EXECUTION_BUFFER_TIME)
            revert DeadlineNotOver();

        delete jobs[key];

        // slash Execution node

        uint256 len = selectedExecutors[key].length;
        for (uint256 index = 0; index < len; index++) {
            address executorKey = selectedExecutors[key][index];
            if(hasExecutedJob[key][executorKey])
                revert JobAlreadyExecuted();
            delete hasExecutedJob[key][executorKey];
            executors.updateOnExecutionTimeoutSlash(executorKey);
        }

        emit SlashedOnExecutionTimeout(_jobId, _reqChainId, selectedExecutors[key]);

        delete selectedExecutors[key];
    }

    function reassignGatewayRelay(
        address _gatewayKeyOld,
        uint256 _jobId,
        uint256 _reqChainId,
        bytes memory _signature,
        uint8 _sequenceId
    ) external {
        uint256 key = getKey(_jobId, _reqChainId);
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected

        if(jobs[key].isResourceUnavailable)
            revert JobMarkedEndedAsResourceUnavailable();
        if(_sequenceId != jobs[key].sequenceId + 1 || _sequenceId > 2)
            revert InvalidSequenceId();
        jobs[key].sequenceId = _sequenceId;

        // signature check
        bytes32 digest = keccak256(abi.encodePacked(_jobId, _reqChainId, _gatewayKeyOld, _sequenceId));
        address signer = digest.recover(_signature);

        gateways.allowOnlyVerified(signer);

        emit GatewayReassigned(_jobId, _reqChainId, _gatewayKeyOld, _msgSender(), _sequenceId);

        // slash old gateway
    }

    //-------------------------------- Timeout end --------------------------------//

    function getSelectedExecutors(
        uint256 _jobId,
        uint256 _reqChainId
    ) external view returns (address[] memory) {
        uint256 key = getKey(_jobId, _reqChainId);
        return selectedExecutors[key];
    }
}