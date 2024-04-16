// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./CommonChainExecutors.sol";
import "./CommonChainGateways.sol";

contract CommonChainJobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    UUPSUpgradeable // public upgrade
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IERC20 _token,
        uint256 _relayBufferTime,
        uint256 _executionBufferTime,
        uint256 _noOfNodesToSelect
    ) initializer {
        require(address(_token) != address(0), "ZERO_ADDRESS_TOKEN");
        TOKEN = _token;
        RELAY_BUFFER_TIME = _relayBufferTime;
        EXECUTION_BUFFER_TIME = _executionBufferTime;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;
    }

    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "only admin");
        _;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(bytes32 role, address account) internal virtual override(AccessControlEnumerableUpgradeable) returns (bool) {
        return super._grantRole(role, account);
    }

    function _revokeRole(bytes32 role, address account) internal virtual override(AccessControlEnumerableUpgradeable) returns (bool) {
        bool res = super._revokeRole(role, account);

        // protect against accidentally removing all admins
        require(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0, "AV:RR-All admins cant be removed");
        return res;
    }

    function _authorizeUpgrade(
        address /*account*/
    ) internal view override onlyAdmin {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    function __CommonChainJobs_init(
        address _admin,
        CommonChainGateways _gateways,
        CommonChainExecutors _executors
    ) public initializer {
        require(_admin != address(0), "ZERO_ADDRESS_ADMIN");

        __Context_init();
        __ERC165_init();
        __AccessControlEnumerable_init();
        __UUPSUpgradeable_init();

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

    function setGatewaysContract(CommonChainGateways _gateways) external onlyAdmin {
        gateways = _gateways;
    }

    function setExecutorsContract(CommonChainExecutors _executors) external onlyAdmin {
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
        require(block.timestamp <= _jobRequestTimestamp + RELAY_BUFFER_TIME, "RELAY_TIME_OVER");
        require(!jobs[key].isResourceUnavailable, "JOB_MARKED_ENDED_AS_RESOURCE_UNAVAILABLE");
        require(_sequenceId == jobs[key].sequenceId + 1, "INVALID_SEQUENCE_ID");
        require(jobs[key].execStartTime == 0, "JOB_ALREADY_RELAYED");
        require(gateways.isChainSupported(_reqChainId), "UNSUPPORTED_CHAIN");

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
        require(
            block.timestamp <= jobs[key].execStartTime + jobs[key].deadline + EXECUTION_BUFFER_TIME, 
            "EXECUTION_TIME_OVER"
        );

        // signature check
        bytes32 digest = keccak256(
            abi.encodePacked(_jobId, _reqChainId, _output, _totalTime, _errorCode)
        );
        address signer = digest.recover(_signature);

        executors.allowOnlyVerified(signer);

        require(isJobExecutor(_jobId, _reqChainId, signer), "NOT_SELECTED_EXECUTOR");
        require(!hasExecutedJob[key][signer], "EXECUTOR_ALREADY_SUBMITTED_OUTPUT");

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

    function slashOnExecutionTimeout(
        uint256 _jobId,
        uint256 _reqChainId
    ) external {
        uint256 key = getKey(_jobId, _reqChainId);
        require(jobs[key].jobId > 0, "INVALID_JOB");

        // check for time
        require(
            block.timestamp > jobs[key].execStartTime + jobs[key].deadline + EXECUTION_BUFFER_TIME,
            "DEADLINE_NOT_OVER"
        );

        delete jobs[key];

        // slash Execution node

        uint256 len = selectedExecutors[key].length;
        for (uint256 index = 0; index < len; index++) {
            address executorKey = selectedExecutors[key][index];
            require(!hasExecutedJob[key][executorKey], "JOB_ALREADY_EXECUTED");
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

        require(!jobs[key].isResourceUnavailable, "JOB_MARKED_ENDED_AS_RESOURCE_UNAVAILABLE");
        require(_sequenceId == jobs[key].sequenceId + 1 && _sequenceId < 3, "INVALID_SEQUENCE_ID");
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