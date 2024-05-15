// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./Executors.sol";
import "./Gateways.sol";

contract Jobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, 
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error JobsZeroAddressToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IERC20 _token,
        uint256 _relayBufferTime,
        uint256 _executionBufferTime,
        uint256 _noOfNodesToSelect,
        uint256 _executorFeePerMs,
        uint256 _stakingRewardPerMs
    ) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert JobsZeroAddressToken();
        TOKEN = _token;
        RELAY_BUFFER_TIME = _relayBufferTime;
        EXECUTION_BUFFER_TIME = _executionBufferTime;
        NO_OF_NODES_TO_SELECT = _noOfNodesToSelect;

        EXECUTOR_FEE_PER_MS = _executorFeePerMs;
        STAKING_REWARD_PER_MS = _stakingRewardPerMs;
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

    error JobsZeroAddressAdmin();

    function initialize(
        address _admin,
        Gateways _gateways,
        Executors _executors
    ) public initializer {
        if(_admin == address(0))
            revert JobsZeroAddressAdmin();

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

    Gateways public gateways;
    Executors public executors;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable RELAY_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable NO_OF_NODES_TO_SELECT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTOR_FEE_PER_MS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable STAKING_REWARD_PER_MS;

    function setGatewaysContract(Gateways _gateways) external onlyRole(DEFAULT_ADMIN_ROLE) {
        gateways = _gateways;
    }

    function setExecutorsContract(Executors _executors) external onlyRole(DEFAULT_ADMIN_ROLE) {
        executors = _executors;
    }

    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 jobId;
        uint256 deadline;   // in milliseconds
        uint256 execStartTime;
        address jobOwner;
        address gateway;
        uint256 executionTime;   // it stores the execution time for first output submitted only (in milliseconds)
        uint8 outputCount;
        uint8 sequenceId;
        bool isResourceUnavailable;
    }

    // jobKey => Job
    mapping(uint256 => Job) public jobs;

    // jobKey => executors
    mapping(uint256 => address[]) public selectedExecutors;
    // jobKey => selectedExecutor => hasExecuted
    mapping(uint256 => mapping(address => bool)) public hasExecutedJob;

    bytes32 private constant DOMAIN_SEPARATOR = 
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Jobs"),
                keccak256("1")
            )
        );
    
    bytes32 private constant RELAY_JOB_TYPEHASH = 
        keccak256("RelayJob(address gateway,uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner)");

    bytes32 private constant SUBMIT_OUTPUT_TYPEHASH = 
        keccak256("SubmitOutput(address executor,uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode)");

    bytes32 private constant REASSIGN_GATEWAY_TYPEHASH = 
        keccak256("ReassignGateway(address gateway,uint256 jobId,address gatewayOld,uint8 sequenceId,uint256 jobRequestTimestamp)");

    event JobRelayed(
        uint256 indexed jobId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 deadline,   // in milliseconds
        address jobOwner,
        address gateway,
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
        address indexed gateway
    );

    error JobsRelayTimeOver();
    error JobsJobMarkedEndedAsResourceUnavailable();
    error JobsInvalidSequenceId();
    error JobsJobAlreadyRelayed();
    error JobsUnsupportedChain();
    error JobsExecutionTimeOver();
    error JobsNotSelectedExecutor();
    error JobsExecutorAlreadySubmittedOutput();

    //-------------------------------- internal functions start --------------------------------//

    function _relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,  // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        address _gateway
    ) internal {
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert JobsRelayTimeOver();
        if(jobs[_jobId].isResourceUnavailable)
            revert JobsJobMarkedEndedAsResourceUnavailable();
        if(jobs[_jobId].execStartTime != 0)
            revert JobsJobAlreadyRelayed();
        if(_sequenceId != jobs[_jobId].sequenceId + 1)
            revert JobsInvalidSequenceId();
        
        // first 64 bits represent chainId
        uint256 reqChainId = _jobId >> 192;
        if(!gateways.isChainSupported(reqChainId))
            revert JobsUnsupportedChain();

        // signature check
        _verifyRelaySign(_signature, _gateway, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner);

        address[] memory selectedNodes = executors.selectExecutors(NO_OF_NODES_TO_SELECT);
        // if no executors are selected, then mark isRosourceAvailable flag of the job and exit
        if(selectedNodes.length < NO_OF_NODES_TO_SELECT) {
            jobs[_jobId].isResourceUnavailable = true;
            emit JobResourceUnavailable(_jobId, _gateway);
            return;
        }
        selectedExecutors[_jobId] = selectedNodes;

        // deposit escrow amount(USDC)
        TOKEN.safeTransferFrom(_gateway, address(this), _deadline * (EXECUTOR_FEE_PER_MS + STAKING_REWARD_PER_MS));

        _relay(_jobId, _codehash, _codeInputs, _deadline, _sequenceId, _jobOwner, _gateway, selectedNodes);
    }

    function _verifyRelaySign(
        bytes memory _signature,
        address _gateway,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,  // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                RELAY_JOB_TYPEHASH,
                _gateway,
                _jobId,
                _codehash,
                keccak256(_codeInputs),
                _deadline,
                _jobRequestTimestamp,
                _sequenceId,
                _jobOwner
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        gateways.allowOnlyVerified(signer, _gateway);
    }

    function _relay(
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,  // in milliseconds
        uint8 _sequenceId,
        address _jobOwner,
        address _gateway,
        address[] memory _selectedNodes
    ) internal {
        jobs[_jobId].jobId = _jobId;
        jobs[_jobId].deadline = _deadline;
        jobs[_jobId].execStartTime = block.timestamp;
        jobs[_jobId].jobOwner = _jobOwner;
        jobs[_jobId].gateway = _gateway;
        jobs[_jobId].sequenceId = _sequenceId;

        emit JobRelayed(_jobId, _codehash, _codeInputs, _deadline, _jobOwner, _gateway, _selectedNodes);
    }

    function _submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode,
        address _executor
    ) internal {
        if((block.timestamp * 1000) > (jobs[_jobId].execStartTime * 1000) + jobs[_jobId].deadline + (EXECUTION_BUFFER_TIME * 1000))
            revert JobsExecutionTimeOver();

        // signature check
        _verifyOutputSign(_signature, _executor, _jobId, _output, _totalTime, _errorCode);

        if(!_isJobExecutor(_jobId, _executor))
            revert JobsNotSelectedExecutor();
        if(hasExecutedJob[_jobId][_executor])
            revert JobsExecutorAlreadySubmittedOutput();

        executors.releaseExecutor(_executor);
        hasExecutedJob[_jobId][_executor] = true;

        uint8 outputCount = ++jobs[_jobId].outputCount;
        if(outputCount == 1)
            jobs[_jobId].executionTime = _totalTime;

        // on reward distribution, 1st output executor node gets max reward
        // reward ratio - 2:1:0
        _transferRewardPayout(_jobId, outputCount, _executor);

        emit JobResponded(_jobId, _output, _totalTime, _errorCode, outputCount);
    }

    // TODO: this sign can be used at a later time for new job with same jobId and assigned executor
    function _verifyOutputSign(
        bytes memory _signature,
        address _executor,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                SUBMIT_OUTPUT_TYPEHASH,
                _executor,
                _jobId,
                keccak256(_output),
                _totalTime,
                _errorCode
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        executors.allowOnlyVerified(signer, _executor);
    }

    function _transferRewardPayout(
        uint256 _jobId,
        uint256 _outputCount,
        address _executor
    ) internal {
        uint256 executionTime = jobs[_jobId].executionTime;
        // for first output
        if(_outputCount == 1) {
            // transfer payout to executor
            TOKEN.safeTransfer(_executor, (executionTime * EXECUTOR_FEE_PER_MS * 2) / 3);
            // TODO: is payment pool the jobs contract itself?
            // // transfer payout to payment pool
            // TOKEN.safeTransfer(address(this), executionTime * STAKING_REWARD_PER_MS);
        }
        // for second output
        else if(_outputCount == 2) {
            // transfer payout to executor
            TOKEN.safeTransfer(_executor, (executionTime * EXECUTOR_FEE_PER_MS) / 3);
        }
        // for 3rd output
        else {
            uint256 executorPayout = executionTime * EXECUTOR_FEE_PER_MS;
            uint256 paymentPoolPayout = executionTime * STAKING_REWARD_PER_MS;
            uint256 gatewayDeposit = jobs[_jobId].deadline * (EXECUTOR_FEE_PER_MS + STAKING_REWARD_PER_MS);
            uint256 gatewayPayout = gatewayDeposit - paymentPoolPayout - executorPayout;
            // transfer payout to gateway
            TOKEN.safeTransfer(jobs[_jobId].gateway, gatewayPayout);

            // cleanup job data after 3rd output submitted
            _cleanJobData(_jobId, _executor);
        }
    }

    function _cleanJobData(
        uint256 _jobId,
        address _executor
    ) internal {
        delete jobs[_jobId];

        uint256 len = selectedExecutors[_jobId].length;
        for (uint256 index = 0; index < len; index++) {
            delete hasExecutedJob[_jobId][_executor];
        }

        delete selectedExecutors[_jobId];
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
        uint256 _deadline,  // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner
    ) external {
        _relayJob(_signature, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner, _msgSender());
    }

    function submitOutput(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) external {
        _submitOutput(_signature, _jobId, _output, _totalTime, _errorCode, _msgSender());
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
        address prevGateway,
        address reporterGateway,
        uint8 sequenceId
    );

    error JobsInvalidJob();
    error JobsDeadlineNotOver();

    //-------------------------------- internal functions start ----------------------------------//

    function _slashOnExecutionTimeout(
        uint256 _jobId
    ) internal {
        if(jobs[_jobId].jobId == 0)
            revert JobsInvalidJob();

        // check for time
        if((block.timestamp * 1000) <= (jobs[_jobId].execStartTime * 1000) + jobs[_jobId].deadline + (EXECUTION_BUFFER_TIME * 1000))
            revert JobsDeadlineNotOver();

        address gateway = jobs[_jobId].gateway;
        address jobOwner = jobs[_jobId].jobOwner;
        uint8 outputCount = jobs[_jobId].outputCount;
        bool isNoOutputSubmitted = (outputCount == 0);
        uint256 deadline = jobs[_jobId].deadline;
        uint256 executionTime = jobs[_jobId].executionTime;
        delete jobs[_jobId];

        _releaseEscrowAmount(gateway, outputCount, isNoOutputSubmitted, deadline, executionTime);

        // slash Execution node
        uint256 len = selectedExecutors[_jobId].length;
        for (uint256 index = 0; index < len; index++) {
            address executor = selectedExecutors[_jobId][index];

            if(!hasExecutedJob[_jobId][executor]) {
                executors.slashExecutor(
                    executor,
                    isNoOutputSubmitted,
                    gateway,
                    jobOwner
                );
                emit SlashedOnExecutionTimeout(_jobId, executor);
            }
            delete hasExecutedJob[_jobId][executor];
        }

        delete selectedExecutors[_jobId];
    }

    function _releaseEscrowAmount(
        address _gateway,
        uint8 _outputCount,
        bool _isNoOutputSubmitted,
        uint256 _deadline,
        uint256 _executionTime
    ) internal {
        uint256 gatewayDeposit = _deadline * (EXECUTOR_FEE_PER_MS + STAKING_REWARD_PER_MS);
        uint256 gatewayPayout;
        
        // transfer back the whole escrow amount to gateway if no output submitted
        if(_isNoOutputSubmitted)
            gatewayPayout = gatewayDeposit;
        else {
            uint256 paymentPoolPayout = _executionTime * STAKING_REWARD_PER_MS;
            uint256 executorPayout = _executionTime * EXECUTOR_FEE_PER_MS;
            
            if(_outputCount == 1) {
                uint256 executor1Payout = (executorPayout * 2) / 3;
                gatewayPayout = gatewayDeposit - paymentPoolPayout - executor1Payout;
            }
            // if only 2 outputs submitted
            else
                gatewayPayout = gatewayDeposit - paymentPoolPayout - executorPayout;
        }

        TOKEN.safeTransfer(_gateway, gatewayPayout);
    }

    function _reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        address _gateway
    ) internal {
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert JobsRelayTimeOver();

        if(jobs[_jobId].isResourceUnavailable)
            revert JobsJobMarkedEndedAsResourceUnavailable();
        if(_sequenceId != jobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert JobsInvalidSequenceId();
        jobs[_jobId].sequenceId = _sequenceId;

        // signature check
        _verifyReassignGatewaySign(_signature, _gateway, _jobId, _gatewayOld, _sequenceId, _jobRequestTimestamp);

        // slash old gateway
        gateways.slashOnReassignGateway(_sequenceId, _gatewayOld, _gateway, _jobOwner);
        
        emit GatewayReassigned(_jobId, _gatewayOld, _gateway, _sequenceId);
    }

    function _verifyReassignGatewaySign(
        bytes memory _signature,
        address _gateway,
        uint256 _jobId,
        address _gatewayOld,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                REASSIGN_GATEWAY_TYPEHASH,
                _gateway,
                _jobId,
                _gatewayOld,
                _sequenceId,
                _jobRequestTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        gateways.allowOnlyVerified(signer, _gateway);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function slashOnExecutionTimeout(
        uint256 _jobId
    ) external {
        _slashOnExecutionTimeout(_jobId);
    }

    function reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner
    ) external {
        _reassignGatewayRelay(_gatewayOld, _jobId, _signature, _sequenceId, _jobRequestTimestamp, _jobOwner, _msgSender());
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Timeout end --------------------------------//

    function getSelectedExecutors(
        uint256 _jobId
    ) external view returns (address[] memory) {
        return selectedExecutors[_jobId];
    }
}