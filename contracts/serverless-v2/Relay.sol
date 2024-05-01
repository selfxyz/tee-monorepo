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
import "../interfaces/IAttestationVerifier.sol";

contract Relay is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error RelayInvalidToken();
    error RelayInvalidGlobalTimeouts();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier, 
        uint256 maxAge,
        IERC20 _token,
        uint256 _globalMinTimeout,
        uint256 _globalMaxTimeout,
        uint256 _overallTimeout
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();
        
        if(address(_token) == address(0))
            revert RelayInvalidToken();
        TOKEN = _token;

        if(_globalMinTimeout >= _globalMaxTimeout)
            revert RelayInvalidGlobalTimeouts();
        GLOBAL_MIN_TIMEOUT = _globalMinTimeout;
        GLOBAL_MAX_TIMEOUT = _globalMaxTimeout;
        OVERALL_TIMEOUT = _overallTimeout;
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

    error RelayZeroAddressAdmin();

    function initialize(
        address _admin,
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert RelayZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobCount = block.chainid << 192;
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Gateway start --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MIN_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable GLOBAL_MAX_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable OVERALL_TIMEOUT;

    // enclaveKey => Gateway operator
    mapping(address => address) public gatewayOperators;

    event GatewayRegistered(
        address indexed enclaveKey,
        address indexed operator
    );

    event GatewayDeregistered(address indexed enclaveKey);

    error RelayGatewayAlreadyExists();
    error RelayInvalidGatewayOperator();

    //-------------------------------- internal functions start --------------------------------//

    function _registerGateway(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestation, IAttestationVerifier.Attestation(_enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds));

        
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gatewayOperators[enclaveKey] != address(0))
            revert RelayGatewayAlreadyExists();
        gatewayOperators[enclaveKey] = _msgSender();

        emit GatewayRegistered(enclaveKey, _msgSender());
    }

    function _deregisterGateway(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gatewayOperators[enclaveKey] != _msgSender())
            revert RelayInvalidGatewayOperator();
        delete gatewayOperators[enclaveKey];

        _revokeEnclaveKey(enclaveKey);

        emit GatewayDeregistered(enclaveKey);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    function registerGateway(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds
    ) external {
        _registerGateway(_attestation, _enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds);
    }

    function deregisterGateway(
        bytes memory _enclavePubKey
    ) external {
        _deregisterGateway(_enclavePubKey);
    }

    //-------------------------------- external functions end ---------------------------//

    //-------------------------------- Gateway End --------------------------------//


    //-------------------------------- Job start --------------------------------//

    struct Job {
        uint256 startTime;
        uint256 maxGasPrice;
        uint256 usdcDeposit;
        uint256 callbackDeposit;
        address jobOwner;
    }

    mapping(uint256 => Job) public jobs;

    uint256 public jobCount;

    bytes32 private constant DOMAIN_SEPARATOR = 
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Relay"),
                keccak256("1")
            )
        );
    
    bytes32 private constant JOB_RESPONSE_TYPEHASH = 
        keccak256("JobResponse(address operator,uint256 jobId,bytes output,uint256 totalTime,uint8 errorCode)");

    event JobRelayed(
        uint256 indexed jobId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 userTimeout,    // in milliseconds
        uint256 maxGasPrice,
        uint256 usdcDeposit,
        uint256 callbackDeposit, 
        uint256 startTime
    );

    event JobResponded(
        uint256 indexed jobId,
        bytes output,
        uint256 totalTime,
        uint256 errorCode,
        bool success
    );

    event JobCancelled(uint256 indexed jobId);

    error RelayInvalidUserTimeout();
    error RelayJobNotExists();
    error RelayOverallTimeoutOver();
    error RelayInvalidJobOwner();
    error RelayOverallTimeoutNotOver();

    //-------------------------------- internal functions start -------------------------------//

    // TODO: create deposits of USDC and native token
    function _relayJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _userTimeout,   // in milliseconds
        uint256 _maxGasPrice,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) internal {
        if(_userTimeout <= (GLOBAL_MIN_TIMEOUT * 1000) || _userTimeout >= (GLOBAL_MAX_TIMEOUT * 1000))
            revert RelayInvalidUserTimeout();

        if (jobCount + 1 == (block.chainid + 1) << 192)
            jobCount = block.chainid << 192;

        jobs[++jobCount] = Job({
            startTime: block.timestamp,
            maxGasPrice: _maxGasPrice,
            usdcDeposit: _usdcDeposit,
            callbackDeposit: _callbackDeposit,
            jobOwner: _msgSender()
        });

        emit JobRelayed(jobCount, _codehash, _codeInputs, _userTimeout, _maxGasPrice, _usdcDeposit, _callbackDeposit, block.timestamp);
    }

    function _jobResponse(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) internal {
        if(jobs[_jobId].jobOwner == address(0))
            revert RelayJobNotExists();

        // check time case
        if(block.timestamp > jobs[_jobId].startTime + OVERALL_TIMEOUT)
            revert RelayOverallTimeoutOver();

        // signature check
        bytes32 hashStruct = keccak256(
            abi.encode(
                JOB_RESPONSE_TYPEHASH,
                _msgSender(),
                _jobId,
                keccak256(_output),
                _totalTime,
                _errorCode
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);

        bool success = _callBackWithLimit(_jobId, _output, _errorCode);

        emit JobResponded(_jobId, _output, _totalTime, _errorCode, success);

        // TODO: release escrow

        delete jobs[_jobId];
    }

    function _jobCancel(
        uint256 _jobId
    ) internal {
        if(jobs[_jobId].jobOwner != _msgSender())
            revert RelayInvalidJobOwner();
            
        // check time case
        if(block.timestamp <= jobs[_jobId].startTime + OVERALL_TIMEOUT)
            revert RelayOverallTimeoutNotOver();

        delete jobs[_jobId];
        emit JobCancelled(_jobId);

        // release escrow 
    }

    function _callBackWithLimit(
        uint256 _jobId, 
        bytes memory _input, 
        uint8 _errorCode
    ) internal returns (bool) {
        // uint start_gas = gasleft();
        Job memory job = jobs[_jobId];
        (bool success,) = job.jobOwner.call{gas: (job.callbackDeposit / tx.gasprice)}(
            abi.encodeWithSignature("oysterResultCall(uint256,bytes,uint8)", _jobId, _input, _errorCode)
        );
        // offsetting the gas consumed by wrapping methods, calculated manually by checking callback_cost when deposit is 0
        // uint callback_cost = (start_gas - gasleft() - MinCallbackGas) * tx.gasprice;
        // payable(_job.provider).transfer(_job_cost + callback_cost);
        // payable(_job.sender).transfer(_job.off_chain_deposit - _job_cost + _job.callback_deposit - callback_cost);
        return success;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    function relayJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) external payable {
        _relayJob(_codehash, _codeInputs, _userTimeout, _maxGasPrice, _usdcDeposit, _callbackDeposit);
    }

    // TODO: pass executorAddress for billing and check 2:1:0 ratio logic for rewards
    function jobResponse(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) external {
        _jobResponse(_signature, _jobId, _output, _totalTime, _errorCode);
    }

    function jobCancel(
        uint256 _jobId
    ) external {
        _jobCancel(_jobId);
    }

    //-------------------------------- external functions end --------------------------------//

    //-------------------------------- Job End --------------------------------//

}
