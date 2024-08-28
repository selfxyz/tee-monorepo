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
import "../interfaces/IAttestationVerifier.sol";
import "./Relay.sol";

/**
 * @title RelaySubscriptions Contract
 * @notice This contract manages serverless job subscriptions.
 * @dev This contract is upgradeable and uses the UUPS (Universal Upgradeable Proxy Standard) pattern.
 */
contract RelaySubscriptions is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable // public upgrade
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    /// @notice Error for when zero address is provided for Relay contract.
    error RelaySubscriptionsInvalidRelay();
    /// @notice Error for when zero address token is provided.
    error RelaySubscriptionsInvalidToken();
    /// @notice Error for when global timeout values are invalid (minimum timeout is not less than maximum timeout).
    error RelaySubscriptionsInvalidGlobalTimeouts();

    /**
     * @notice Initializes the logic contract with essential parameters and disables further 
     * initializations of the logic contract.
     * @param _relay The Relay contract.
     * @param _token The ERC20 token used for payments and deposits.
     * @param _signMaxAge The maximum age of a valid signature in seconds.
     * @param _globalMinTimeout The minimum timeout value for jobs.
     * @param _globalMaxTimeout The maximum timeout value for jobs. This refers to the max time for the executor to execute the job.
     * @param _overallTimeout The overall timeout value for job execution. This refers to the max time for the complete lifecycle of the job request on-chain.
     * @param _executionFeePerMs The fee per millisecond for job execution(in USDC).
     * @param _gatewayFeePerJob The fixed fee per job for the gateway(in USDC).
     * @param _fixedGas The fixed gas amount for job responses without callback.
     * @param _callbackMeasureGas The gas amount used for measuring callback gas.
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        Relay _relay,
        IERC20 _token,
        uint256 _globalMinTimeout, // in milliseconds
        uint256 _globalMaxTimeout, // in milliseconds
        uint256 _overallTimeout,
        uint256 _signMaxAge,
        uint256 _executionFeePerMs, // fee is in USDC
        uint256 _gatewayFeePerJob,
        uint256 _fixedGas,
        uint256 _callbackMeasureGas
    ) {
        _disableInitializers();

        RELAY = _relay;
        if (address(_token) == address(0)) revert RelaySubscriptionsInvalidToken();
        TOKEN = _token;
        SIGN_MAX_AGE = _signMaxAge;

        if (_globalMinTimeout >= _globalMaxTimeout) revert RelaySubscriptionsInvalidGlobalTimeouts();
        GLOBAL_MIN_TIMEOUT = _globalMinTimeout;
        GLOBAL_MAX_TIMEOUT = _globalMaxTimeout;
        OVERALL_TIMEOUT = _overallTimeout;

        EXECUTION_FEE_PER_MS = _executionFeePerMs;
        GATEWAY_FEE_PER_JOB = _gatewayFeePerJob;

        FIXED_GAS = _fixedGas;
        CALLBACK_MEASURE_GAS = _callbackMeasureGas;
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

    /// @notice Error for when zero address is provided for the admin.
    error RelaySubscriptionsZeroAddressAdmin();

    /**
     * @notice Initializes the Relay contract with the specified admin and enclave images.
     * @param _admin The address to be granted the DEFAULT_ADMIN_ROLE.
     */
    function initialize(address _admin) public initializer {
        if (_admin == address(0)) revert RelaySubscriptionsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobSubsCount = (block.chainid << 192) | uint256(1) << 191;
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    Relay public immutable RELAY;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SIGN_MAX_AGE;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MIN_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable OVERALL_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_FEE_PER_MS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GATEWAY_FEE_PER_JOB;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable FIXED_GAS; // Should equal to gas of jobResponse without callback - gas refunds

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable CALLBACK_MEASURE_GAS; // gas consumed for measurement of callback gas

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.RelaySubscriptions"),
                keccak256("1")
            )
        );

    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 startTime;
        uint256 maxGasPrice;
        uint256 usdcDeposit;
        uint256 callbackDeposit;
        uint256 callbackGasLimit;
        address jobOwner;
        address callbackContract;
        bytes32 codehash;
        bytes codeInputs;
    }

    bytes32 private constant JOB_RESPONSE_TYPEHASH =
        keccak256("JobResponse(uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode,uint256 signTimestamp)");

    /// @notice Error for when the signature has expired.
    error RelaySubscriptionsSignatureTooOld();

    function _verifyJobResponseSign(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal view returns (address) {
        if (block.timestamp > _signTimestamp + SIGN_MAX_AGE) revert RelaySubscriptionsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(JOB_RESPONSE_TYPEHASH, _jobId, keccak256(_output), _totalTime, _errorCode, _signTimestamp)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        RELAY.allowOnlyVerified(signer);
        return signer;
    }

    function _callBackWithLimit(
        uint256 _jobId,
        Job memory _job,
        bytes calldata _output,
        uint8 _errorCode
    ) internal returns (bool success, uint callbackGas) {
        if (tx.gasprice <= _job.maxGasPrice) {
            uint startGas = gasleft();
            (success, ) = _job.callbackContract.call{gas: _job.callbackGasLimit}(
                abi.encodeWithSignature(
                    "oysterResultCall(uint256,address,bytes32,bytes,bytes,uint8)",
                    _jobId,
                    _job.jobOwner,
                    _job.codehash,
                    _job.codeInputs,
                    _output,
                    _errorCode
                )
            );
            // calculate callback cost
            callbackGas = startGas - gasleft();
        }
    }

    //-------------------------------- internal functions end ----------------------------------//

    //--------------------------------------- Job end ----------------------------------------//

    //-------------------------------- Job Subscription Start ----------------------------------//

    struct JobSubscription {
        uint256 periodicGap;
        uint256 terminationTimestamp;
        uint256 currentRuns;
        uint256 lastRunTimestamp;
        uint256 userTimeout;
        address refundAccount;
        Job job;
    }

    // jobSubsId => JobSubscription
    mapping(uint256 => JobSubscription) public jobSubscriptions;

    /**
     * @notice Tracks the job subscriptions count.
     * @dev It follows this scheme - 
     *      | Chain ID (64)| 1 (1 bit) | sub_id (64 bits) | instance_count (127) |
     *      First 64 bits represent the chainId.
     *      65th bit is fixed as 1, which represents a job subscription.
     *      Next 64 bits are reserved for subscription id, and increments each time a new job subscrtiption is started.
     *      Last 127 bits are fixed as all zeros.
     *      If sub_id reaches its max value, then we reset the sub_id to zero.
     */
    uint256 public jobSubsCount;

    /**
     * @notice Emitted when a job subscription is started.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param jobSubscriber The address of the job subscriber.
     * @param periodicGap The gap between job executions in the subscription.
     * @param usdcDeposit The USDC deposit provided for the subscription.
     * @param terminationTimestamp The timestamp when the subscription should terminate.
     * @param userTimeout The timeout specified by the user for the subscription.
     * @param refundAccount The address where the refund will be sent.
     * @param codehash The transaction hash storing the code to be executed.
     * @param codeInputs The inputs for the code execution.
     * @param startTime The timestamp when the subscription was started.
     */
    event JobSubscriptionStarted(
        uint256 indexed jobSubsId,
        address indexed jobSubscriber,
        uint256 periodicGap,
        uint256 usdcDeposit,
        uint256 terminationTimestamp,
        uint256 userTimeout,
        address refundAccount,
        bytes32 codehash,
        bytes codeInputs,
        uint256 startTime
    );

    /**
     * @notice Emitted when a job subscription responds with its output.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param output The output from the job execution.
     * @param totalTime The total time taken for the job execution.
     * @param errorCode The error code if the job failed.
     * @param success A boolean indicating if the job was successful.
     * @param currentRuns The number of times the job has run.
     * @param lastRunTimestamp The timestamp of the last job run.
     */
    event JobSubscriptionResponded(
        uint256 indexed jobSubsId,
        bytes output,
        uint256 totalTime,
        uint256 errorCode,
        bool success,
        uint256 currentRuns,
        uint256 lastRunTimestamp
    );

    /**
     * @notice Emitted when USDC or callback deposit is made for a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param depositor The address making the deposit.
     * @param usdcDeposit The amount of USDC deposited.
     * @param callbackDeposit The amount of callback deposit made.
     */
    event JobSubscriptionFundsDeposited(
        uint256 indexed jobSubsId,
        address indexed depositor,
        uint256 usdcDeposit,
        uint256 callbackDeposit
    );

    /**
     * @notice Emitted when job parameters are updated in a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param _codehash The new code hash for the job.
     * @param _codeInputs The new code inputs for the job.
     */
    event JobSubscriptionJobParamsUpdated(
        uint256 indexed jobSubsId,
        bytes32 _codehash,
        bytes _codeInputs
    );

    /**
     * @notice Emitted when termination parameters are updated in a job subscription.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param terminationTimestamp The new termination timestamp for the subscription.
     */
    event JobSubscriptionTerminationParamsUpdated(
        uint256 indexed jobSubsId,
        // uint256 maxRuns,
        uint256 terminationTimestamp
    );

    /**
     * @notice Emitted when job subscription remaining funds are withdrawn.
     * @param jobSubsId The unique identifier of the job subscription.
     * @param withdrawer The address withdrawing the funds.
     * @param usdcAmountWithdrawn The amount of USDC withdrawn.
     * @param callbackAmountWithdrawn The amount of callback deposit withdrawn.
     * @param success A boolean indicating if the withdrawal was successful.
     */
    event JobSubscriptionFundsWithdrawn(
        uint256 indexed jobSubsId,
        address indexed withdrawer,
        uint256 usdcAmountWithdrawn,
        uint256 callbackAmountWithdrawn,
        bool success
    );

    /**
     * @notice Emitted when job subscription is terminated.
     * param jobSubsId The unique identifier of the job subscription.
     */
    event JobSubscriptionTerminated(
        uint256 indexed jobSubsId
    );

    /// @notice Error for when a job subscription is invalid.
    error RelaySubscriptionsInvalidJobSubscription();
    /// @notice Error for when the current runs in job response jobId is invalid.
    error RelaySubscriptionsInvalidCurrentRuns();
    /// @notice Error for when insufficient USDC is being deposited for a job subscription.
    error RelaySubscriptionsInsufficientUsdcDeposit();
    /// @notice Error for when the start timestamp is an invalid value.
    error RelaySubscriptionsInvalidStartTimestamp();
    /// @notice Error for when an invalid user timeout is provided.
    error RelaySubscriptionsInvalidUserTimeout();
    /// @notice Error for when the maximum gas price provided is insufficient.
    error RelaySubscriptionsInsufficientMaxGasPrice();
    /// @notice Error for when there is insufficient callback deposit.
    error RelaySubscriptionsInsufficientCallbackDeposit();
    /// @notice Error for when the overall timeout for a job has been exceeded.
    error RelaySubscriptionsOverallTimeoutOver();
    /// @notice Error for when the termination timestamp is an invalid value.
    error RelaySubscriptionsInvalidTerminationTimestamp();
    /// @notice Error for when the termination timestamp is being updated after the termination condition is reached.
    error RelaySubscriptionsJobSubscriptionTerminated();
    /// @notice Error for when the msg.sender isn't the job subscription owner
    error RelaySubscriptionsNotJobSubscriptionOwner();
    /// @notice Error for when the job subscription owner tries to terminate the subscription 
    ///         before the termination condition is reached.
    error RelaySubscriptionsTerminationConditionPending();
    //-------------------------------- internal functions start --------------------------------//

    function _startJobSubscription(
        bytes32 _codehash,
        bytes calldata _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        address _refundAccount,
        address _callbackContract,
        uint256 _callbackGasLimit,
        uint256 _periodicGap,
        uint256 _usdcDeposit,
        uint256 _startTimestamp,
        uint256 _terminationTimestamp,
        address _jobOwner
    ) internal {
        // TODO: Can _terminationTimestamp = 0 and _maxRuns = 0 while starting subscription??

        if(_startTimestamp >= _terminationTimestamp)
            revert RelaySubscriptionsInvalidStartTimestamp();

        if(_terminationTimestamp <= block.timestamp)
            revert RelaySubscriptionsInvalidTerminationTimestamp();

        if (_userTimeout <= GLOBAL_MIN_TIMEOUT || _userTimeout >= GLOBAL_MAX_TIMEOUT) 
            revert RelaySubscriptionsInvalidUserTimeout();

        if (_maxGasPrice < tx.gasprice) 
            revert RelaySubscriptionsInsufficientMaxGasPrice();

        if(_startTimestamp < block.timestamp)
            _startTimestamp = block.timestamp;

        _validateDeposits(_userTimeout, _maxGasPrice, _callbackGasLimit, _periodicGap, _usdcDeposit, _startTimestamp, _terminationTimestamp);

        Job memory job = Job({
            startTime: _startTimestamp,
            maxGasPrice: _maxGasPrice,
            usdcDeposit: _usdcDeposit,
            callbackDeposit: msg.value,
            jobOwner: _jobOwner,
            codehash: _codehash,
            codeInputs: _codeInputs,
            callbackContract: _callbackContract,
            callbackGasLimit: _callbackGasLimit
        });

        _createJobSubscription(
            job,
            _userTimeout,
            _refundAccount,
            _periodicGap,
            _startTimestamp,
            _terminationTimestamp,
            _jobOwner
        );

        // deposit escrow amount(USDC) for the periodic jobs
        TOKEN.safeTransferFrom(_jobOwner, address(this), _usdcDeposit);
    }

    function _validateDeposits(
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _callbackGasLimit,
        uint256 _periodicGap,
        uint256 _usdcDeposit,
        uint256 _startTimestamp,
        uint256 _terminationTimestamp
    ) internal {
        uint256 totalRuns = (_terminationTimestamp - _startTimestamp) / _periodicGap;
        if (_maxGasPrice * (_callbackGasLimit + FIXED_GAS + CALLBACK_MEASURE_GAS) * totalRuns > msg.value)
            revert RelaySubscriptionsInsufficientCallbackDeposit();

        uint256 minUsdcDeposit = (_userTimeout * EXECUTION_FEE_PER_MS + GATEWAY_FEE_PER_JOB) * totalRuns;
        if(_usdcDeposit < minUsdcDeposit)
            revert RelaySubscriptionsInsufficientUsdcDeposit();
    }

    function _createJobSubscription(
        Job memory _job,
        uint256 _userTimeout,
        address _refundAccount,
        uint256 _periodicGap,
        uint256 _startTimestamp,
        uint256 _terminationTimestamp,
        address _jobOwner
    ) internal {
        _updateJobSubsCount();

        jobSubscriptions[jobSubsCount] = JobSubscription({
            periodicGap: _periodicGap,
            terminationTimestamp: _terminationTimestamp,
            currentRuns: 0,
            lastRunTimestamp: 0,
            userTimeout: _userTimeout,
            refundAccount: _refundAccount,
            job: _job
        });

        emit JobSubscriptionStarted(
            jobSubsCount,
            _jobOwner,
            _periodicGap,
            _job.usdcDeposit,
            _terminationTimestamp,
            _userTimeout,
            _refundAccount,
            _job.codehash,
            _job.codeInputs,
            _startTimestamp
        );
    }

    function _updateJobSubsCount() internal {
        uint256 subId = (jobSubsCount >> 127) & ((1 << 64) - 1);
        if(subId == 2**64 - 1)
            jobSubsCount = (block.chainid << 192) | uint256(1) << 191;
        jobSubsCount += (uint256(1) << 127);
    }

    function _jobSubsResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) internal {
        // setting the last 127 bits as zero to get the jobSubsId
        uint256 jobSubsId = (_jobId >> 127) << 127;
        JobSubscription memory jobSubs = jobSubscriptions[jobSubsId];
        if (jobSubs.job.jobOwner == address(0)) 
            revert RelaySubscriptionsInvalidJobSubscription();

        // getting the virtual start time of the job subscription current run
        uint256 jobStartTime = jobSubs.job.startTime + (jobSubs.currentRuns * jobSubs.periodicGap);
        if(block.timestamp > jobStartTime + OVERALL_TIMEOUT)
            revert RelaySubscriptionsOverallTimeoutOver();

        uint256 instanceCount = _jobId & ((1 << 127) - 1);
        // note: instance count for the first output should be 0
        if(instanceCount < jobSubs.currentRuns)
            revert RelaySubscriptionsInvalidCurrentRuns();

        // signature check
        address enclaveAddress = _verifyJobResponseSign(
            _signature,
            _jobId,
            _output,
            _totalTime,
            _errorCode,
            _signTimestamp
        );

        jobSubscriptions[jobSubsId].currentRuns = instanceCount + 1;
        jobSubscriptions[jobSubsId].lastRunTimestamp = block.timestamp;

        _releaseJobSubsEscrowAmount(enclaveAddress, _totalTime, jobSubs.job.usdcDeposit);

        (bool success, uint256 callbackGas) = _callBackWithLimit(
            jobSubsId,
            jobSubs.job,
            _output,
            _errorCode
        );

        // TODO: FIXED_GAS will be different for this function
        uint256 callbackCost = (callbackGas + FIXED_GAS) * tx.gasprice;

        _releaseJobSubsGasCostOnSuccess(RELAY.gatewayOwners(enclaveAddress), jobSubs.job.callbackDeposit, callbackCost);

        emit JobSubscriptionResponded(
            jobSubsId,
            _output,
            _totalTime,
            _errorCode,
            success,
            instanceCount,
            block.timestamp
        );
    }

    function _releaseJobSubsEscrowAmount(
        address _enclaveAddress,
        uint256 _totalTime,
        uint256 _usdcDeposit
    ) internal {
        uint256 gatewayPayoutUsdc;
        uint256 jobOwnerPayoutUsdc;
        unchecked {
            gatewayPayoutUsdc = _totalTime * EXECUTION_FEE_PER_MS + GATEWAY_FEE_PER_JOB;
            jobOwnerPayoutUsdc = _usdcDeposit - gatewayPayoutUsdc;
        }

        // release escrow to gateway
        TOKEN.safeTransfer(RELAY.gatewayOwners(_enclaveAddress), gatewayPayoutUsdc);

        jobSubscriptions[jobSubsCount].job.usdcDeposit = jobOwnerPayoutUsdc;
    }

    function _releaseJobSubsGasCostOnSuccess(
        address _gatewayOwner,
        uint256 _callbackDeposit,
        uint256 _callbackCost
    ) internal {
        // TODO: If paySuccess is false then deposit will be stucked forever. Find a way out.
        // transfer callback cost to gateway
        _callbackCost = _callbackCost > _callbackDeposit ? _callbackDeposit : _callbackCost;
        (bool paySuccess, ) = _gatewayOwner.call{value: _callbackCost}("");

        // transfer remaining native asset to the jobOwner
        jobSubscriptions[jobSubsCount].job.callbackDeposit -= _callbackCost;
    }

    function _depositJobSubscriptionFunds(
        uint256 _jobSubsId,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) internal {
        if(jobSubscriptions[_jobSubsId].job.jobOwner == address(0))
            revert RelaySubscriptionsInvalidJobSubscription();

        _depositTokens(_jobSubsId, _usdcDeposit, _callbackDeposit);
    }

    function _depositTokens(
        uint256 _jobSubsId,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) internal {
        TOKEN.safeTransferFrom(_msgSender(), address(this), _usdcDeposit);

        jobSubscriptions[_jobSubsId].job.usdcDeposit += _usdcDeposit;
        jobSubscriptions[_jobSubsId].job.callbackDeposit += _callbackDeposit;
        emit JobSubscriptionFundsDeposited(_jobSubsId, _msgSender(), _usdcDeposit, _callbackDeposit);
    }

    function _updateJobSubsJobParams(
        uint256 _jobSubsId,
        bytes32 _codehash,
        bytes calldata _codeInputs
    ) internal {
        if(jobSubscriptions[_jobSubsId].job.jobOwner != _msgSender())
            revert RelaySubscriptionsNotJobSubscriptionOwner();

        jobSubscriptions[_jobSubsId].job.codehash = _codehash;
        jobSubscriptions[_jobSubsId].job.codeInputs = _codeInputs;

        emit JobSubscriptionJobParamsUpdated(_jobSubsId, _codehash, _codeInputs);
    }

    function _updateJobSubsTerminationParams(
        uint256 _jobSubsId,
        uint256 _terminationTimestamp,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) internal {
        if(jobSubscriptions[_jobSubsId].job.jobOwner != _msgSender())
            revert RelaySubscriptionsNotJobSubscriptionOwner();

        if(_terminationTimestamp < block.timestamp + OVERALL_TIMEOUT)
            revert RelaySubscriptionsInvalidTerminationTimestamp();
        
        if(block.timestamp > jobSubscriptions[_jobSubsId].terminationTimestamp)
            revert RelaySubscriptionsJobSubscriptionTerminated();

        // won't be executed if called from terminateJobSubscription()
        if(_terminationTimestamp > block.timestamp + OVERALL_TIMEOUT) {
            _depositTokens(_jobSubsId, _usdcDeposit, _callbackDeposit);

            JobSubscription memory jobSubs = jobSubscriptions[_jobSubsId];
            uint256 remainingRuns = (_terminationTimestamp - block.timestamp) / jobSubs.periodicGap;

            if (jobSubs.job.maxGasPrice * (jobSubs.job.callbackGasLimit + FIXED_GAS + CALLBACK_MEASURE_GAS) * remainingRuns > jobSubs.job.callbackDeposit)
                revert RelaySubscriptionsInsufficientCallbackDeposit();

            uint256 minUsdcDeposit = (jobSubs.userTimeout * EXECUTION_FEE_PER_MS + GATEWAY_FEE_PER_JOB) * remainingRuns;
            if(jobSubs.job.usdcDeposit < minUsdcDeposit)
                revert RelaySubscriptionsInsufficientUsdcDeposit();
        }

        jobSubscriptions[_jobSubsId].terminationTimestamp = _terminationTimestamp;

        emit JobSubscriptionTerminationParamsUpdated(_jobSubsId, _terminationTimestamp);
    }

    function _withdrawJobSubsFunds(
        uint256 _jobSubsId,
        address _jobOwner
    ) internal {
        if(jobSubscriptions[_jobSubsId].job.jobOwner != _jobOwner)
            revert RelaySubscriptionsNotJobSubscriptionOwner();

        if(block.timestamp <= jobSubscriptions[_jobSubsId].terminationTimestamp + OVERALL_TIMEOUT)
            revert RelaySubscriptionsTerminationConditionPending();

        uint256 usdcAmount = jobSubscriptions[_jobSubsId].job.usdcDeposit;
        uint256 callbackAmount = jobSubscriptions[_jobSubsId].job.callbackDeposit;

        delete jobSubscriptions[_jobSubsId];

        TOKEN.safeTransfer(_jobOwner, usdcAmount);
        // TODO: do we need to check this bool success
        (bool success, ) = _jobOwner.call{value: callbackAmount}("");

        emit JobSubscriptionFundsWithdrawn(_jobSubsId, _jobOwner, usdcAmount, callbackAmount, success);
    }

    function _terminateJobSubscription(
        uint256 _jobSubsId
    ) internal {
        _updateJobSubsTerminationParams(_jobSubsId, block.timestamp + OVERALL_TIMEOUT, 0, 0);

        emit JobSubscriptionTerminated(_jobSubsId);
    }

    //-------------------------------- internal functions end --------------------------------//

    //-------------------------------- external functions start --------------------------------//

    /**
     * @notice Starts a subscription for periodic job execution.
     * @dev The subscription parameters are validated, and the necessary deposits(USDC+ETH) are made.
     * @param _codehash The transaction hash storing the code to be executed periodically.
     * @param _codeInputs The inputs to the code to be executed periodically.
     * @param _userTimeout The maximum execution time allowed for each job in milliseconds.
     * @param _maxGasPrice The maximum gas price the subscriber is willing to pay to get back the job response.
     * @param _refundAccount The account to receive any remaining/slashed tokens.
     * @param _callbackContract The contract address to be called upon submitting job response.
     * @param _callbackGasLimit The gas limit for the callback function.
     * @param _periodicGap The time gap between each job relay in milliseconds.
     * @param _usdcDeposit The amount of USDC to be deposited for the subscription.
     * @param _startTimestamp The timestamp at which the job subscription would activate and start relaying periodic jobs.
     *                        If it's sent as zero, then consider its value to be block.timestamp.
     * @param _terminationTimestamp The timestamp after which no further jobs are relayed.
     */
    function startJobSubscription(
        bytes32 _codehash,
        bytes calldata _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        address _refundAccount,
        address _callbackContract,
        uint256 _callbackGasLimit,
        uint256 _periodicGap,
        uint256 _usdcDeposit,
        uint256 _startTimestamp,
        uint256 _terminationTimestamp
    ) external payable {
        _startJobSubscription(
            _codehash,
            _codeInputs,
            _userTimeout,
            _maxGasPrice,
            _refundAccount,
            _callbackContract,
            _callbackGasLimit,
            _periodicGap,
            _usdcDeposit,
            _startTimestamp,
            _terminationTimestamp,
            _msgSender()
        );
    }

    /**
     * @notice Function for the gateway to respond to a periodic job within a subscription.
     * @dev The response includes output data, execution time, and error code.
     * @param _signature The signature of the gateway enclave verifying the job response.
     * @param _jobId The unique identifier of the job of a specific job subscription. Last 127 bits 
     *               store the current runs count for which the response is being submitted.
     * @param _output The output data from the job execution.
     * @param _totalTime The total time taken for job execution in milliseconds.
     * @param _errorCode The error code returned from the job execution.
     * @param _signTimestamp The timestamp at which the response was signed by the enclave.
     */
    function jobSubsResponse(
        bytes calldata _signature,
        uint256 _jobId,
        bytes calldata _output,
        uint256 _totalTime,
        uint8 _errorCode,
        uint256 _signTimestamp
    ) external {
        _jobSubsResponse(_signature, _jobId, _output, _totalTime, _errorCode, _signTimestamp);
    }

    /**
     * @notice Deposits additional USDC and native assets(ETH) for a job subscription.
     * @dev This function allows the subscriber to top up their subscription balance.
     * @param _jobSubsId The unique identifier of the job subscription.
     * @param _usdcDeposit The amount of USDC to be deposited.
     */
    function depositJobSubscriptionFunds(
        uint256 _jobSubsId,
        uint256 _usdcDeposit
    ) external payable {
        _depositJobSubscriptionFunds(_jobSubsId, _usdcDeposit, msg.value);
    }

    /**
     * @notice Updates the job parameters for a specific job subscription.
     * @dev This function allows the subscriber to modify the job execution code and input parameters
     *      for an existing subscription. The new parameters will be used in subsequent
     *      job executions within the subscription.
     * @param _jobSubsId The unique identifier of the job subscription to be updated.
     * @param _codehash The new transaction hash storing the code that will be executed by the enclave.
     * @param _codeInputs The new input parameters for the code to be executed.
     */
    function updateJobSubsJobParams(
        uint256 _jobSubsId,
        bytes32 _codehash,
        bytes calldata _codeInputs
    ) external {
        _updateJobSubsJobParams(_jobSubsId, _codehash, _codeInputs);
    }

    /**
     * @notice Updates the termination parameters for a specific job subscription.
     * @dev This function allows the subscriber to modify the termination time associated with an 
     *      existing job subscription. It means user might have to deposit additional USDC+ETH if 
     *      termination time is increased, and enought funds weren't deposited initially.
     * @param _jobSubsId The unique identifier of the job subscription to be updated.
     * @param _terminationTimestamp The new timestamp (in seconds) when the job subscription will terminate.
     * @param _usdcDeposit The additional amount of USDC to be deposited.
     */
    function updateJobSubsTerminationParams(
        uint256 _jobSubsId,
        uint256 _terminationTimestamp,
        uint256 _usdcDeposit
    ) external payable {
        _updateJobSubsTerminationParams(_jobSubsId, _terminationTimestamp, _usdcDeposit, msg.value);
    }

    /**
     * @notice Allows job subscription remaining fund withdrawal once the termination condition is reached.
     * @dev This function deletes the job subscription data and refunds the deposited USDC and ETH, if any.
     * param _jobSubsId The unique identifier of the job subscription.
     */
    function withdrawJobSubsFunds(
        uint256 _jobSubsId
    ) external {
        _withdrawJobSubsFunds(_jobSubsId, _msgSender());
    }

    /**
     * @notice For advance termination of job subscription.
     * param _jobSubsId The unique identifier of the job subscription.
     */
    function terminateJobSubscription(
        uint256 _jobSubsId
    ) external {
        _terminateJobSubscription(_jobSubsId);
    }

    //-------------------------------- external functions end --------------------------------//

    //-------------------------------- Job Subscription End --------------------------------//
}