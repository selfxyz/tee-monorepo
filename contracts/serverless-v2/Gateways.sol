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
import "./Jobs.sol";

contract Gateways is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, 
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error GatewaysZeroAddressToken();
    error GatewaysZeroAddressUsdcToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        IERC20 _token_usdc,
        uint256 _deregisterOrUnstakeTimeout,
        uint256 _reassignCompForReporterGateway,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips,
        uint256 _relayBufferTime,
        uint256 _executionFeePerMs,
        uint256 _slashCompForGateway
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert GatewaysZeroAddressToken();
        TOKEN = _token;

        if (address(_token_usdc) == address(0))
            revert GatewaysZeroAddressUsdcToken();
        TOKEN_USDC = _token_usdc;

        DEREGISTER_OR_UNSTAKE_TIMEOUT = _deregisterOrUnstakeTimeout;

        REASSIGN_COMP_FOR_REPORTER_GATEWAY = _reassignCompForReporterGateway;
        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
        RELAY_BUFFER_TIME = _relayBufferTime;
        EXECUTION_FEE_PER_MS = _executionFeePerMs;
        SLASH_COMP_FOR_GATEWAY = _slashCompForGateway;
    }

    //-------------------------------- Overrides start --------------------------------//

    error GatewaysZeroAddressAdmin();

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

    function initialize(
        address _admin,
        EnclaveImage[] memory _images,
        Jobs _job_mgr
    ) public initializer {
        if(_admin == address(0))
            revert GatewaysZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        
        job_mgr = _job_mgr;
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN_USDC;

    Jobs public job_mgr;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable DEREGISTER_OR_UNSTAKE_TIMEOUT;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable REASSIGN_COMP_FOR_REPORTER_GATEWAY;

    /// @notice an integer in the range 0-10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice expected to be 10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable RELAY_BUFFER_TIME;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable EXECUTION_FEE_PER_MS;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_COMP_FOR_GATEWAY;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    function setJobsContract(Jobs _job_mgr) external onlyRole(DEFAULT_ADMIN_ROLE) {
        job_mgr = _job_mgr;
    }

    //-------------------------------- Gateway start --------------------------------//

    modifier isValidGateway(
        address _gateway
    ) {
        if(gateways[_gateway].enclaveAddress == address(0))
            revert GatewaysInvalidGateway();
        _;
    }

    struct RequestChain {
        address contractAddress;
        string httpRpcUrl;
        string wsRpcUrl;
    }

    mapping(uint256 => RequestChain) public requestChains;

    struct Gateway {
        address enclaveAddress;
        uint256[] chainIds;
        uint256 stakeAmount;
        uint256 deregisterStartTime;
        bool status;
        uint256 unstakeStartTime;
    }

    struct Job {
        uint256 execStartTime;
        bool isResourceUnavailable;
        uint8 sequenceId;
        address jobOwner;
        address gateway;
        uint256 usdcDeposit;
    }

    // gateway => Gateway
    mapping(address => Gateway) public gateways;

    // job_id => job
    mapping(uint256 => Job) public relay_jobs;

    mapping(uint256 => uint256) public exec_jobs;

    bytes32 private constant DOMAIN_SEPARATOR = 
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Gateways"),
                keccak256("1")
            )
        );
    
    bytes32 private constant REGISTER_TYPEHASH = 
        keccak256("Register(address gateway,uint256[] chainIds)");
    bytes32 private constant ADD_CHAINS_TYPEHASH = 
        keccak256("AddChains(address gateway,uint256[] chainIds)");
    bytes32 private constant REMOVE_CHAINS_TYPEHASH = 
        keccak256("RemoveChains(address gateway,uint256[] chainIds)");

    bytes32 private constant RELAY_JOB_TYPEHASH = 
        keccak256("RelayJob(address gateway,uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner)");

    bytes32 private constant REASSIGN_GATEWAY_TYPEHASH = 
        keccak256("ReassignGateway(address gateway,uint256 jobId,address gatewayOld,uint8 sequenceId,uint256 jobRequestTimestamp)");

    event GatewayRegistered(
        address indexed gateway,
        address indexed enclaveAddress,
        uint256[] chainIds
    );

    event GatewayDeregistered(address indexed gateway);

    event GatewayDeregisterCompleted(address indexed gateway);

    event GatewayStakeAdded(
        address indexed gateway,
        uint256 addedAmount
    );

    event GatewayStakeRemoveInitiated(address indexed gateway);

    event GatewayStakeRemoved(
        address indexed gateway,
        uint256 removedAmount
    );

    event ChainAddedGlobal(
        uint256 chainId,
        address contractAddress,
        string httpRpcUrl,
        string wsRpcUrl
    );

    event ChainRemovedGlobal(
        uint256 chainId
    );

    event ChainAdded(
        address indexed gateway,
        uint256 chainId
    );

    event ChainRemoved(
        address indexed gateway,
        uint256 chainId
    );

    event GatewayReassigned(
        uint256 indexed jobId,
        address prevGateway,
        address reporterGateway,
        uint8 sequenceId
    );

    event JobCreated(
        uint256 indexed jobId,
        uint256 execJobId,
        address jobOwner,
        address gateway
    );

    event JobResponded(
        uint256 indexed jobId,
        bytes output,
        uint256 totalTime,
        uint8 errorCode
    );
    
    event JobFailed(
        uint256 indexed jobId
    );

    error GatewaysInvalidSigner();
    error GatewaysGatewayAlreadyExists();
    error GatewaysUnsupportedChain();
    error GatewaysInvalidStatus();
    error GatewaysDeregisterNotInitiated();
    error GatewaysDeregisterTimePending();
    error GatewaysDeregisterAlreadyInitiated();
    error GatewaysStakeRemoveAlreadyInitiated();
    error GatewaysUnstakeTimePending();
    error GatewaysInvalidAmount();
    error GatewaysInvalidLength();
    error GatewaysEmptyRequestedChains();
    error GatewaysChainAlreadyExists(uint256 chainId);
    error GatewaysEmptyChainlist();
    error GatewaysChainNotFound(uint256 chainId);
    error GatewaysInvalidGateway();
    error GatewaysJobRelayTimeOver();
    error GatewaysJobResourceUnavailable();
    error GatewaysJobAlreadyRelayed();
    error GatewaysInvalidRelaySequenceId();
    // error GatewaysUnsupportedChain();

    //-------------------------------- internal functions start ----------------------------------//

    function _registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _gateway
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifyRegisterSign(_gateway, _chainIds, _signature, enclaveAddress);
        
        if(gateways[_gateway].enclaveAddress != address(0))
            revert GatewaysGatewayAlreadyExists();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            if(requestChains[_chainIds[index]].contractAddress == address(0))
                revert GatewaysUnsupportedChain();
        }

        // check missing for validating chainIds array for multiple same chainIds

        _register(_gateway, enclaveAddress, _chainIds);

        _addStake(_gateway, _stakeAmount);
    }

    function _verifyRegisterSign(
        address _gateway,
        uint256[] memory _chainIds,
        bytes memory _signature,
        address _enclaveAddress
    ) internal pure {
        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function _register(
        address _gateway,
        address _enclaveAddress,
        uint256[] memory _chainIds
    ) internal {
        gateways[_gateway].enclaveAddress = _enclaveAddress;
        gateways[_gateway].chainIds = _chainIds;
        gateways[_gateway].status = true;

        emit GatewayRegistered(_gateway, _enclaveAddress, _chainIds);
    }

    function _deregisterGateway(
        address _gateway
    ) internal {
        if(gateways[_gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();

        gateways[_gateway].status = false;
        gateways[_gateway].deregisterStartTime = block.timestamp;

        emit GatewayDeregistered(_gateway);
    }

    function _completeDeregistration(
        address _gateway
    ) internal {
        if(gateways[_gateway].deregisterStartTime == 0)
            revert GatewaysDeregisterNotInitiated();
        if(block.timestamp <= gateways[_gateway].deregisterStartTime + DEREGISTER_OR_UNSTAKE_TIMEOUT)
            revert GatewaysDeregisterTimePending();

        _removeStake(_gateway, gateways[_gateway].stakeAmount);
        
        _revokeEnclaveKey(gateways[_gateway].enclaveAddress);
        delete gateways[_gateway];

        emit GatewayDeregisterCompleted(_gateway);
    }

    function _addGatewayStake(
        uint256 _amount,
        address _gateway
    ) internal {
        _addStake(_gateway, _amount);
    }

    // TODO: check if the gateway is assigned some job before full stake removal
    function _removeGatewayStake(
        address _gateway
    ) internal {
        if(gateways[_gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();
        if(gateways[_gateway].unstakeStartTime > 0)
            revert GatewaysStakeRemoveAlreadyInitiated();

        gateways[_gateway].status = false;
        gateways[_gateway].unstakeStartTime = block.timestamp;

        emit GatewayStakeRemoveInitiated(_gateway);
    }

    function _completeRemoveGatewayStake(
        uint256 _amount,
        address _gateway
    ) internal {
        if(gateways[_gateway].status)
            revert GatewaysInvalidStatus();
        if(gateways[_gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();
        if(block.timestamp <= gateways[_gateway].unstakeStartTime + DEREGISTER_OR_UNSTAKE_TIMEOUT)
            revert GatewaysUnstakeTimePending();

        _amount = _amount < gateways[_gateway].stakeAmount ? _amount : gateways[_gateway].stakeAmount;
        if(_amount == 0)
            revert GatewaysInvalidAmount();

        gateways[_gateway].unstakeStartTime = 0;
        gateways[_gateway].status = true;

        _removeStake(_gateway, _amount);
    }

    function _addChainGlobal(
        uint256[] memory _chainIds,
        RequestChain[] memory _requestChains
    ) internal {
        if(_chainIds.length == 0 || _chainIds.length != _requestChains.length)
            revert GatewaysInvalidLength();
        for (uint256 index = 0; index < _requestChains.length; index++) {
            RequestChain memory reqChain = _requestChains[index];
            uint256 chainId = _chainIds[index];
            requestChains[chainId] = reqChain;

            emit ChainAddedGlobal(chainId, reqChain.contractAddress, reqChain.httpRpcUrl, reqChain.wsRpcUrl);
        }
    }

    function _removeChainGlobal(
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysInvalidLength();
        for (uint256 index = 0; index < _chainIds.length; index++) {
            uint256 chainId = _chainIds[index];
            delete requestChains[chainId];

            emit ChainRemovedGlobal(chainId);
        }
    }

    function _addChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        address _gateway
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyAddChainsSign(_signature, _gateway, _chainIds);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(_chainIds[index], _gateway);
        }
    }

    function _verifyAddChainsSign(
        bytes memory _signature,
        address _gateway,
        uint256[] memory _chainIds
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ADD_CHAINS_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != gateways[_gateway].enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function _addChain(
        uint256 _chainId,
        address _gateway
    ) internal {
        if(requestChains[_chainId].contractAddress == address(0))
            revert GatewaysUnsupportedChain();

        uint256[] memory chainIdList = gateways[_gateway].chainIds;
        for (uint256 index = 0; index < chainIdList.length; index++) {
            if(chainIdList[index] == _chainId)
                revert GatewaysChainAlreadyExists(_chainId);
        }
        gateways[_gateway].chainIds.push(_chainId);

        emit ChainAdded(_gateway, _chainId);
    }

    function _removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        address _gateway
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyRemoveChainsSign(_signature, _gateway, _chainIds);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(_chainIds[index], _gateway);
        }
    }

    function _verifyRemoveChainsSign(
        bytes memory _signature,
        address _gateway,
        uint256[] memory _chainIds
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                REMOVE_CHAINS_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != gateways[_gateway].enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function _removeChain(
        uint256 _chainId,
        address _gateway
    ) internal {
        uint256[] memory chainIdList = gateways[_gateway].chainIds;
        uint256 len = chainIdList.length;
        if(len == 0)
            revert GatewaysEmptyChainlist();

        uint256 index = 0;
        for (; index < len; index++) {
            if (chainIdList[index] == _chainId) 
                break;
        }

        if(index == len)
            revert GatewaysChainNotFound(_chainId);
        if (index != len - 1)
            gateways[_gateway].chainIds[index] = gateways[_gateway].chainIds[len - 1];

        gateways[_gateway].chainIds.pop();

        emit ChainRemoved(_gateway, _chainId);
    }

    function _addStake(
        address _gateway,
        uint256 _amount
    ) internal {
        gateways[_gateway].stakeAmount += _amount;
        // transfer stake
        TOKEN.safeTransferFrom(_gateway, address(this), _amount);

        emit GatewayStakeAdded(_gateway, _amount);
    }

    function _removeStake(
        address _gateway,
        uint256 _amount
    ) internal {
        gateways[_gateway].stakeAmount -= _amount;
        // transfer stake
        TOKEN.safeTransfer(_gateway, _amount);

        emit GatewayStakeRemoved(_gateway, _amount);
    }

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
            revert GatewaysJobRelayTimeOver();
        // TODO: check if can remove Resource Unavialble check
        if(relay_jobs[_jobId].isResourceUnavailable)
            revert GatewaysJobResourceUnavailable();
        if(relay_jobs[_jobId].execStartTime != 0)
            revert GatewaysJobAlreadyRelayed();
        if(_sequenceId != relay_jobs[_jobId].sequenceId + 1)
            revert GatewaysInvalidRelaySequenceId();
        uint256 reqChainId = _jobId >> 192;
        if(requestChains[reqChainId].contractAddress == address(0))
            revert GatewaysUnsupportedChain();
        
        // signature check
        _verifyRelaySign(_signature, _gateway, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner);

        // reserve execution fee from gateway
        uint256 usdcDeposit = _deadline * EXECUTION_FEE_PER_MS;
        TOKEN_USDC.safeTransferFrom(_gateway, address(this), usdcDeposit);
        (uint256 execJobId, uint8 errorCode) = job_mgr.createJob(_codehash, _codeInputs, _deadline); 
        if (errorCode == 1) {
            // Resource unavailable
            relay_jobs[_jobId].isResourceUnavailable = true;
            return;
        }

        _createJob(_jobId, execJobId, _jobOwner, _gateway, usdcDeposit);
    }

    function _createJob(
        uint256 _jobId,
        uint256 _execJobId,
        address _jobOwner,
        address _gateway,
        uint256 _usdcDeposit
    ) internal {
        relay_jobs[_jobId].execStartTime = block.timestamp;
        relay_jobs[_jobId].jobOwner = _jobOwner;
        relay_jobs[_jobId].usdcDeposit = _usdcDeposit;
        exec_jobs[_execJobId] = _jobId;
        emit JobCreated(_jobId, _execJobId, _jobOwner, _gateway);
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

        _allowOnlyVerifiedGateway(signer, _gateway);
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
            revert GatewaysJobRelayTimeOver();

        if(relay_jobs[_jobId].isResourceUnavailable)
            revert GatewaysJobResourceUnavailable();
        if(_sequenceId != relay_jobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert GatewaysInvalidRelaySequenceId();
        relay_jobs[_jobId].sequenceId = _sequenceId;

        // signature check
        _verifyReassignGatewaySign(_signature, _gateway, _jobId, _gatewayOld, _sequenceId, _jobRequestTimestamp);

        // slash old gateway
        _slashOnReassignGateway(_sequenceId, _gatewayOld, _gateway, _jobOwner);
        
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

        _allowOnlyVerifiedGateway(signer, _gateway);
    }

    function _allowOnlyVerifiedGateway(
        address _enclaveAddress,
        address _gateway
    ) internal view {
        _allowOnlyVerified(_enclaveAddress);
        if(_enclaveAddress != gateways[_gateway].enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function _slashOnReassignGateway(
        uint8 _sequenceId,
        address _oldGateway,
        address _reporterGateway,
        address _jobOwner
    ) internal {
        uint256 totalComp = gateways[_oldGateway].stakeAmount * SLASH_PERCENT_IN_BIPS / SLASH_MAX_BIPS;
        gateways[_oldGateway].stakeAmount -= totalComp;

        // transfer comp to reporter gateway
        TOKEN.safeTransfer(_reporterGateway, REASSIGN_COMP_FOR_REPORTER_GATEWAY);

        // if sequenceId = 1, keep the comp in common pool(gateway contract)
        // if sequenceId = 2, transfer comp to jobOwner
        if (_sequenceId == 2) {
            TOKEN.safeTransfer(_jobOwner, totalComp - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        }
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

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

    function registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerGateway(_attestationSignature, _attestation, _chainIds, _signature, _stakeAmount, _msgSender());
    }

    function deregisterGateway() external isValidGateway(_msgSender()) {
        _deregisterGateway(_msgSender());
    }

    function completeDeregistration() external isValidGateway(_msgSender()) {
        _completeDeregistration(_msgSender());
    }

    function addGatewayStake(
        uint256 _amount
    ) external isValidGateway(_msgSender()) {
        _addGatewayStake(_amount, _msgSender());
    }

    function removeGatewayStake() external isValidGateway(_msgSender()) {
        _removeGatewayStake(_msgSender());
    }

    function completeRemoveGatewayStake(
        uint256 _amount
    ) external isValidGateway(_msgSender()) {
        _completeRemoveGatewayStake(_amount, _msgSender());
    }

    function addChainGlobal(
        uint256[] memory _chainIds,
        RequestChain[] memory _requestChains
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addChainGlobal(_chainIds, _requestChains);
    }

    function removeChainGlobal(
        uint256[] memory _chainIds
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _removeChainGlobal(_chainIds);
    }

    function addChains(
        bytes memory _signature,
        uint256[] memory _chainIds
    ) external isValidGateway(_msgSender()) {
        _addChains(_signature, _chainIds, _msgSender());
    }

    function removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds
    ) external isValidGateway(_msgSender()) {
        _removeChains(_signature, _chainIds, _msgSender());
    }

    function isChainSupported(
        uint256 _reqChainId
    ) external view returns (bool) {
        return (requestChains[_reqChainId].contractAddress != address(0));
    }

    function getGatewayChainIds(
        address _gateway
    ) external view returns (uint256[] memory) {
        return gateways[_gateway].chainIds;
    }

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
        _relayJob(_signature, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner,
                  _msgSender());
    }

    function reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner
    ) external {
        _reassignGatewayRelay(_gatewayOld, _jobId, _signature, _sequenceId, _jobRequestTimestamp, _jobOwner,
        _msgSender());
    }


    
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//
    
    //-------------------------------- internal functions end ----------------------------------//
    function _oysterResultCall(
        uint256 _execJobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) internal {
        // it should be from jobs contract only
        // emit event for job
        // send fund (USDC)
        // delete job

        uint256 jobId = exec_jobs[_execJobId];
        address gateway = relay_jobs[jobId].gateway;
        uint256 usdcDeposit = relay_jobs[jobId].usdcDeposit;

        delete exec_jobs[_execJobId];
        delete relay_jobs[jobId];

        TOKEN_USDC.safeTransfer(gateway, usdcDeposit - _totalTime * EXECUTION_FEE_PER_MS);
        emit JobResponded(jobId, _output, _totalTime, _errorCode);
    }

    function _oysterFailureCall(uint256 _execJobId, uint256 _slashAmount) internal {
        // it should be from jobs contract only
        // emit event for job
        // send fund (USDC, slashing amounts in POND)
        // delete job
        uint jobId = exec_jobs[_execJobId];
        address gateway = relay_jobs[jobId].gateway;
        uint256 usdcDeposit = relay_jobs[jobId].usdcDeposit;
        address jobOwner = relay_jobs[jobId].jobOwner;
        delete exec_jobs[_execJobId];
        delete relay_jobs[jobId];

        TOKEN_USDC.safeTransfer(gateway, usdcDeposit);
        TOKEN.safeTransfer(jobOwner, _slashAmount - SLASH_COMP_FOR_GATEWAY);
        TOKEN.safeTransfer(gateway, SLASH_COMP_FOR_GATEWAY);
        emit JobFailed(jobId);
    }
    //------------------------------- external functions start ---------------------------------//

    function oysterResultCall(
        uint256 _jobId,
        bytes memory _output,
        uint8 _errorCode,
        uint256 _totalTime
    ) external onlyRole(JOBS_ROLE) {
        // it should be from jobs contract only
        _oysterResultCall(_jobId, _output, _errorCode, _totalTime);
    }

    function oysterFailureCall(uint256 _jobId, uint256 _slashAmount) external onlyRole(JOBS_ROLE) {
        // only the jobs contract
        _oysterFailureCall(_jobId, _slashAmount);
    }
    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
