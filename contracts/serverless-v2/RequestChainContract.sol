// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../AttestationAutherUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";

contract RequestChainContract is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlEnumerableUpgradeable, // RBAC enumeration
    AttestationAutherUpgradeable, 
    UUPSUpgradeable // public upgrade
{
    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier, 
        uint256 maxAge
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) initializer {}

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

    function __RequestChainContract_init(
        address _admin,
        IERC20 _token,
        EnclaveImage[] memory _images,
        uint256 _globalMinTimeout,
        uint256 _globalMaxTimeout,
        uint256 _overallTimeout
    ) public initializer {
        __Context_init();
        __ERC165_init();
        __AccessControlEnumerable_init();
        __AttestationAuther_init_unchained(_images);
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        require(address(_token) != address(0), "INVALID_TOKEN");
        token = _token;

        require(_globalMinTimeout < _globalMaxTimeout, "INVALID_GLOBAL_TIMEOUTS");
        globalMinTimeout = _globalMinTimeout;
        globalMaxTimeout = _globalMaxTimeout;
        overallTimeout = _overallTimeout;
    }

    //-------------------------------- Initializer end --------------------------------//

    //-------------------------------- Gateway start --------------------------------//

    IERC20 public token;

    uint256 public globalMinTimeout;
    uint256 public globalMaxTimeout;
    uint256 public overallTimeout;

    struct Gateway {
        address operator;
        bool status;
    }

    // enclaveKey => Gateway
    mapping(address => Gateway) public gateways;

    modifier onlyGatewayOperator(bytes memory _enclavePubKey) {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        require(
            gateways[enclaveKey].operator == _msgSender(),
            "ONLY_GATEWAY_OPERATOR"
        );
        _;
    }

    event GatewayRegistered(
        bytes enclavePubKey,
        address indexed enclaveAddress,
        address indexed operator
    );

    event GatewayDeregistered(bytes enclavePubKey);

    function registerGateway(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        // uint256 _enclaveCPUs,
        // uint256 _enclaveMemory,
        uint256 _timestampInMilliseconds
    ) external {
        // attestation verification
        // bytes32 imageId = keccak256(abi.encodePacked(_PCR0, _PCR1, _PCR2));
        // _verifyKey(
        //     _attestation, 
        //     _enclavePubKey, 
        //     imageId, 
        //     _enclaveCPUs, 
        //     _enclaveMemory, 
        //     _timestampInMilliseconds
        // );
        _verifyEnclaveKey(_attestation, IAttestationVerifier.Attestation(_enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds));

        
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        gateways[enclaveKey] = Gateway({
            operator: _msgSender(),
            status: true
        });

        emit GatewayRegistered(_enclavePubKey, enclaveKey, _msgSender());
    }

    function deregisterGateway(
        bytes memory _enclavePubKey
    ) external onlyGatewayOperator(_enclavePubKey) {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        require(
            gateways[enclaveKey].operator != address(0),
            "INVALID_ENCLAVE_KEY"
        );
        delete gateways[enclaveKey];

        _revokeEnclaveKey(_enclavePubKey);

        emit GatewayDeregistered(_enclavePubKey);
    }

    //-------------------------------- Gateway End --------------------------------//

    //-------------------------------- Job start --------------------------------//

    struct Job {
        bytes32 codehash;
        bytes codeInputs;
        uint256 userTimeout;
        uint256 startTime;
        uint256 maxGasPrice;
        uint256 usdcDeposit;
        uint256 callbackDeposit;
        address jobOwner;
        bool receivedOutput;
    }

    mapping(uint256 => Job) public jobs;

    uint256 public jobCount;

    modifier onlyJobOwner(uint256 _jobId) {
        require(jobs[_jobId].jobOwner == _msgSender(), "NOT_JOB_OWNER");
        _;
    }

    event JobRelayed(
        uint256 indexed jobId,
        bytes32 codehash,
        bytes codeInputs,
        uint256 userTimeout,
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

    // TODO: create deposits of USDC and native token
    function relayJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) external {
        require(_userTimeout > globalMinTimeout && _userTimeout < globalMaxTimeout, "INVALID_USER_TIMEOUT");
        jobs[++jobCount] = Job({
            codehash: _codehash,
            codeInputs: _codeInputs,
            userTimeout: _userTimeout,
            startTime: block.timestamp,
            maxGasPrice: _maxGasPrice,
            usdcDeposit: _usdcDeposit,
            callbackDeposit: _callbackDeposit,
            jobOwner: _msgSender(),
            receivedOutput: false
        });

        emit JobRelayed(jobCount, _codehash, _codeInputs, _userTimeout, _maxGasPrice, _usdcDeposit, _callbackDeposit, block.timestamp);
    }

    // TODO: pass executorAddress for billing and check 2:1:0 ratio logic for rewards
    function jobResponse(
        bytes memory _signature,
        uint256 _jobId,
        bytes memory _output,
        uint256 _totalTime,
        uint8 _errorCode
    ) external {
        // check time case
        require(block.timestamp <= jobs[_jobId].startTime + overallTimeout, "OVERALL_TIMEOUT_OVER");

        // signature check
        bytes32 digest = keccak256(
            abi.encode(
                _jobId,
                _output,
                _totalTime,
                _errorCode
            )
        );
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);

        jobs[_jobId].receivedOutput = true;

        bool success = _callBackWithLimit(_jobId, _output, _errorCode);

        emit JobResponded(_jobId, _output, _totalTime, _errorCode, success);

        // release escrow


    }

    function jobCancel(
        uint256 _jobId
    ) external onlyJobOwner(_jobId) {
        require(!jobs[_jobId].receivedOutput, "JOB_OUTPUT_ALREADY_RECEIVED");

        // check time case
        require(block.timestamp > jobs[_jobId].startTime + overallTimeout, "OVERALL_TIMEOUT_NOT_OVER");

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
            abi.encodeWithSignature("oysterResultCall(bytes32,bytes,uint8)", _jobId, _input, _errorCode)
        );
        // offsetting the gas consumed by wrapping methods, calculated manually by checking callback_cost when deposit is 0
        // uint callback_cost = (start_gas - gasleft() - MinCallbackGas) * tx.gasprice;
        // payable(_job.provider).transfer(_job_cost + callback_cost);
        // payable(_job.sender).transfer(_job.off_chain_deposit - _job_cost + _job.callback_deposit - callback_cost);
        return success;
    }

    //-------------------------------- Job End --------------------------------//

}
