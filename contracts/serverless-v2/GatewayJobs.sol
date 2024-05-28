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
import "./Gateways.sol";
import "./Jobs.sol";

contract GatewayJobs is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error GatewayJobsZeroAddressStakingToken();
    error GatewayJobsZeroAddressUsdcToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IERC20 _stakingToken,
        IERC20 _usdcToken,
        uint256 _signMaxAge,
        uint256 _relayBufferTime,
        uint256 _executionFeePerMs,
        uint256 _slashCompForGateway,
        uint256 _reassignCompForReporterGateway,
        Jobs _jobMgr,
        Gateways _gateways,
        address _stakingPaymentPoolAddress
    ) {
        _disableInitializers();

        if (address(_stakingToken) == address(0)) revert GatewayJobsZeroAddressStakingToken();
        STAKING_TOKEN = _stakingToken;

        if (address(_usdcToken) == address(0)) revert GatewayJobsZeroAddressUsdcToken();
        USDC_TOKEN = _usdcToken;

        SIGN_MAX_AGE = _signMaxAge;
        RELAY_BUFFER_TIME = _relayBufferTime;
        EXECUTION_FEE_PER_MS = _executionFeePerMs;
        SLASH_COMP_FOR_GATEWAY = _slashCompForGateway;
        REASSIGN_COMP_FOR_REPORTER_GATEWAY = _reassignCompForReporterGateway;
        JOB_MANAGER = _jobMgr;
        GATEWAYS = _gateways;
        STAKING_PAYMENY_POOL = _stakingPaymentPoolAddress;
    }

    //-------------------------------- Overrides start --------------------------------//

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error GatewayJobsZeroAddressAdmin();

    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert GatewayJobsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable STAKING_TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable USDC_TOKEN;

    /// @notice Maximum age of a valid signature, in seconds.
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SIGN_MAX_AGE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable RELAY_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_FEE_PER_MS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_COMP_FOR_GATEWAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable REASSIGN_COMP_FOR_REPORTER_GATEWAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Jobs public immutable JOB_MANAGER;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Gateways public immutable GATEWAYS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address public immutable STAKING_PAYMENY_POOL;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    struct Job {
        uint256 execStartTime;
        bool isResourceUnavailable;
        uint8 sequenceId;
        address jobOwner;
        address gateway;
        uint256 usdcDeposit;
    }

    // job_id => job
    mapping(uint256 => Job) public relayJobs;

    // execution_job_id => job_id
    mapping(uint256 => uint256) public execJobs;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.GatewayJobs"),
                keccak256("1")
            )
        );

    bytes32 private constant RELAY_JOB_TYPEHASH =
        keccak256(
            "RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint256 signTimestamp)"
        );
    bytes32 private constant REASSIGN_GATEWAY_TYPEHASH =
        keccak256(
            "ReassignGateway(uint256 jobId,address gatewayOld,address jobOwner,uint8 sequenceId,uint256 jobRequestTimestamp,uint256 signTimestamp)"
        );

    event JobRelayed(uint256 indexed jobId, uint256 execJobId, address jobOwner, address gateway);

    event JobResourceUnavailable(uint256 indexed jobId, address indexed gateway);

    event GatewayReassigned(uint256 indexed jobId, address prevGateway, address reporterGateway, uint8 sequenceId);

    event JobResponded(uint256 indexed jobId, bytes output, uint256 totalTime, uint8 errorCode);

    event JobFailed(uint256 indexed jobId);

    error GatewayJobsRelayTimeOver();
    error GatewayJobsResourceUnavailable();
    error GatewayJobsAlreadyRelayed();
    error GatewayJobsInvalidRelaySequenceId();
    error GatewayJobsUnsupportedChain();
    error GatewayJobsSignatureTooOld();
    error GatewayJobsCreateFailed(bytes reason);

    //-------------------------------- internal functions start ----------------------------------//

    function _relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint256 _signTimestamp,
        address _gateway
    ) internal {
        if (block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME) revert GatewayJobsRelayTimeOver();
        if (relayJobs[_jobId].isResourceUnavailable) revert GatewayJobsResourceUnavailable();
        if (relayJobs[_jobId].execStartTime != 0) revert GatewayJobsAlreadyRelayed();
        if (_sequenceId != relayJobs[_jobId].sequenceId + 1) revert GatewayJobsInvalidRelaySequenceId();

        uint256 reqChainId = _jobId >> 192;
        if (!GATEWAYS.isChainSupported(reqChainId)) revert GatewayJobsUnsupportedChain();

        // signature check
        address enclaveAddress = _verifyRelaySign(
            _signature,
            _jobId,
            _codehash,
            _codeInputs,
            _deadline,
            _jobRequestTimestamp,
            _sequenceId,
            _jobOwner,
            _signTimestamp
        );

        // reserve execution fee from gateway
        uint256 usdcDeposit = _deadline * EXECUTION_FEE_PER_MS;
        USDC_TOKEN.safeTransferFrom(_gateway, address(this), usdcDeposit);
        USDC_TOKEN.safeIncreaseAllowance(address(JOB_MANAGER), usdcDeposit);

        _createJob(_jobId, _codehash, _codeInputs, _deadline, _jobOwner, enclaveAddress, usdcDeposit, _sequenceId);
    }

    function _createJob(
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,
        address _jobOwner,
        address _gateway,
        uint256 _usdcDeposit,
        uint8 _sequenceId
    ) internal {
        try JOB_MANAGER.createJob(_codehash, _codeInputs, _deadline) returns (uint256 execJobId) {
            relayJobs[_jobId].execStartTime = block.timestamp;
            relayJobs[_jobId].jobOwner = _jobOwner;
            relayJobs[_jobId].usdcDeposit = _usdcDeposit;
            relayJobs[_jobId].sequenceId = _sequenceId;
            relayJobs[_jobId].gateway = _gateway;

            execJobs[execJobId] = _jobId;

            emit JobRelayed(_jobId, execJobId, _jobOwner, _gateway);
        } catch (bytes memory reason) {
            if (bytes4(reason) == Jobs.JobsUnavailableResources.selector) {
                // decrease allowance by _usdcDeposit amount as job failed to relay
                USDC_TOKEN.safeDecreaseAllowance(address(JOB_MANAGER), _usdcDeposit);
                // Resource unavailable
                relayJobs[_jobId].isResourceUnavailable = true;
                // Refund the USDC deposit
                USDC_TOKEN.safeTransfer(_gateway, _usdcDeposit);

                emit JobResourceUnavailable(_jobId, _gateway);
                return;
            } else {
                revert GatewayJobsCreateFailed(reason);
            }
        }
    }

    function _verifyRelaySign(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert GatewayJobsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                RELAY_JOB_TYPEHASH,
                _jobId,
                _codehash,
                keccak256(_codeInputs),
                _deadline,
                _jobRequestTimestamp,
                _sequenceId,
                _jobOwner,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        GATEWAYS.allowOnlyVerified(signer);
        return signer;
    }

    function _reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestamp,
        address _gateway
    ) internal {
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected
        if (block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME) revert GatewayJobsRelayTimeOver();

        if (relayJobs[_jobId].execStartTime != 0) revert GatewayJobsAlreadyRelayed();
        if (relayJobs[_jobId].isResourceUnavailable) revert GatewayJobsResourceUnavailable();
        if (_sequenceId != relayJobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert GatewayJobsInvalidRelaySequenceId();
        relayJobs[_jobId].sequenceId = _sequenceId;

        // signature check
        address enclaveAddress = _verifyReassignGatewaySign(
            _signature,
            _jobId,
            _gatewayOld,
            _jobOwner,
            _sequenceId,
            _jobRequestTimestamp,
            _signTimestamp
        );

        // slash old gateway
        uint256 slashedAmount = GATEWAYS.slashOnReassignGateway(_gatewayOld);
        address _reporterGateway = GATEWAYS.getOwner(enclaveAddress);
        STAKING_TOKEN.safeTransfer(_reporterGateway, REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        if (_sequenceId == 1) {
            // if sequenceId = 1, keep the comp in payment pool
            STAKING_TOKEN.safeTransfer(STAKING_PAYMENY_POOL, slashedAmount - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        } else {
            // if sequenceId = 2, transfer comp to jobOwner
            STAKING_TOKEN.safeTransfer(_jobOwner, slashedAmount - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        }

        emit GatewayReassigned(_jobId, _gatewayOld, _gateway, _sequenceId);
    }

    function _verifyReassignGatewaySign(
        bytes memory _signature,
        uint256 _jobId,
        address _gatewayOld,
        address _jobOwner,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert GatewayJobsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REASSIGN_GATEWAY_TYPEHASH,
                _jobId,
                _gatewayOld,
                _jobOwner,
                _sequenceId,
                _jobRequestTimestamp,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        GATEWAYS.allowOnlyVerified(signer);
        return signer;
    }
    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    function relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline, // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint256 _signTimestamp
    ) external {
        _relayJob(
            _signature,
            _jobId,
            _codehash,
            _codeInputs,
            _deadline,
            _jobRequestTimestamp,
            _sequenceId,
            _jobOwner,
            _signTimestamp,
            _msgSender()
        );
    }

    function reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestamp
    ) external {
        _reassignGatewayRelay(
            _gatewayOld,
            _jobId,
            _signature,
            _sequenceId,
            _jobRequestTimestamp,
            _jobOwner,
            _signTimestamp,
            _msgSender()
        );
    }
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _oysterResultCall(
        uint256 _execJobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) internal {
        uint256 jobId = execJobs[_execJobId];
        address gateway = relayJobs[jobId].gateway;
        uint256 usdcDeposit = relayJobs[jobId].usdcDeposit;

        delete execJobs[_execJobId];
        delete relayJobs[jobId];

        address owner = GATEWAYS.getOwner(gateway);

        USDC_TOKEN.safeTransfer(owner, usdcDeposit - _totalTime * EXECUTION_FEE_PER_MS);
        emit JobResponded(jobId, _output, _totalTime, _errorCode);
    }

    function _oysterFailureCall(uint256 _execJobId, uint256 _slashAmount) internal {
        uint jobId = execJobs[_execJobId];
        address gateway = relayJobs[jobId].gateway;
        uint256 usdcDeposit = relayJobs[jobId].usdcDeposit;
        address jobOwner = relayJobs[jobId].jobOwner;
        delete execJobs[_execJobId];
        delete relayJobs[jobId];

        address gatewayOwner = GATEWAYS.getOwner(gateway);

        USDC_TOKEN.safeTransfer(gatewayOwner, usdcDeposit);
        STAKING_TOKEN.safeTransfer(jobOwner, _slashAmount - SLASH_COMP_FOR_GATEWAY);
        STAKING_TOKEN.safeTransfer(gatewayOwner, SLASH_COMP_FOR_GATEWAY);
        emit JobFailed(jobId);
    }
    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ---------------------------------//

    function oysterResultCall(
        uint256 _jobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) external onlyRole(JOBS_ROLE) {
        _oysterResultCall(_jobId, _output, _errorCode, _totalTime);
    }

    function oysterFailureCall(uint256 _jobId, uint256 _slashAmount) external onlyRole(JOBS_ROLE) {
        _oysterFailureCall(_jobId, _slashAmount);
    }
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//
}
