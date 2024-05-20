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
        IERC20 _tokenUsdc,
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

        if (address(_tokenUsdc) == address(0))
            revert GatewaysZeroAddressUsdcToken();
        TOKEN_USDC = _tokenUsdc;

        DRAINING_TIME_DURATION = _deregisterOrUnstakeTimeout;

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
        Jobs _jobMgr,
        address _paymentPoolAddress
    ) public initializer {
        if(_admin == address(0))
            revert GatewaysZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        jobMgr = _jobMgr;
        paymentPool = _paymentPoolAddress;
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN_USDC;

    Jobs public jobMgr;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable DRAINING_TIME_DURATION;

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

    address public paymentPool;

    //-------------------------------- Gateway start --------------------------------//
    modifier isValidGatewayOwner(
        address _enclaveAddress,
        address _owner
    ) {
        if(gateways[_enclaveAddress].owner != _owner)
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
        address owner;
        uint256[] chainIds;
        uint256 stakeAmount;
        bool draining;
        uint256 drainStartTime;
    }

    struct Job {
        uint256 execStartTime;
        bool isResourceUnavailable;
        uint8 sequenceId;
        address jobOwner;
        address gateway;
        uint256 usdcDeposit;
    }

    // enclaveAddress => Gateway
    mapping(address => Gateway) public gateways;

    // job_id => job
    mapping(uint256 => Job) public relayJobs;

    mapping(uint256 => uint256) public execJobs;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Gateways"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256[] chainIds,uint256 signTimestampInMs)");
    bytes32 private constant ADD_CHAINS_TYPEHASH =
        keccak256("AddChains(uint256[] chainIds,uint256 signTimestampInMs)");
    bytes32 private constant REMOVE_CHAINS_TYPEHASH =
        keccak256("RemoveChains(uint256[] chainIds,uint256 signTimestampInMs)");
    bytes32 private constant RELAY_JOB_TYPEHASH =
        keccak256("RelayJob(uint256 jobId,bytes32 codeHash,bytes codeInputs,uint256 deadline,uint256 jobRequestTimestamp,uint8 sequenceId,address jobOwner,uint256 signTimestampInMs)");
    bytes32 private constant REASSIGN_GATEWAY_TYPEHASH =
        keccak256("ReassignGateway(uint256 jobId,address gatewayOld,uint8 sequenceId,uint256 jobRequestTimestamp,uint256 signTimestampInMs)");

    event GatewayRegistered(
        address indexed enclaveAddress,
        address indexed owner,
        uint256[] chainIds
    );

    event GatewayDeregistered(address indexed enclaveAddress);

    event GatewayStakeAdded(
        address indexed enclaveAddress,
        uint256 addedAmount
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
        address indexed enclaveAddress,
        uint256 chainId
    );

    event ChainRemoved(
        address indexed enclaveAddress,
        uint256 chainId
    );

    event GatewayDrained(
        address indexed enclaveAddress
    );

    event GatewayRevived(
        address indexed enclaveAddress
    );

    event GatewayStakeRemoved(
        address indexed enclaveAddress,
        uint256 removedAmount
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
    error GatewaysSignatureTooOld();
    error GatewaysInvalidLength();
    error GatewaysEmptyRequestedChains();
    error GatewaysChainAlreadyExists(uint256 chainId);
    error GatewaysEmptyChainlist();
    error GatewaysChainNotFound(uint256 chainId);
    error GatewaysInvalidGateway();
    error GatewaysAlreadyDraining();
    error GatewaysDrainPending();
    error GatewaysNotDraining();
    error GatewaysAlreadyRevived();
    error GatewaysJobRelayTimeOver();
    error GatewaysJobResourceUnavailable();
    error GatewaysJobAlreadyRelayed();
    error GatewaysInvalidRelaySequenceId();

    //-------------------------------- Admin methods start --------------------------------//

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

    function setJobsContract(Jobs _jobMgr) external onlyRole(DEFAULT_ADMIN_ROLE) {
        jobMgr = _jobMgr;
    }

    function setPaymentPool(address _paymentPoolAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        paymentPool = _paymentPoolAddress;
    }

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

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        uint256 _signTimestampInMs,
        address _owner
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifyRegisterSign(_owner, _chainIds, _signTimestampInMs, _signature, enclaveAddress);

        if(gateways[enclaveAddress].owner != address(0))
            revert GatewaysGatewayAlreadyExists();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            if(requestChains[_chainIds[index]].contractAddress == address(0))
                revert GatewaysUnsupportedChain();
        }

        // TODO: check missing for validating chainIds array for multiple same chainIds

        _register(enclaveAddress, _owner, _chainIds);

        _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifyRegisterSign(
        address _owner,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        bytes memory _signature,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > (_signTimestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _owner,
                keccak256(abi.encodePacked(_chainIds)),
                _signTimestampInMs
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function _register(
        address _enclaveAddress,
        address _owner,
        uint256[] memory _chainIds
    ) internal {
        gateways[_enclaveAddress].owner = _owner;
        gateways[_enclaveAddress].chainIds = _chainIds;

        emit GatewayRegistered(_enclaveAddress, _owner, _chainIds);
    }

    function _drainGateway(
        address _enclaveAddress
    ) internal {
        if (gateways[_enclaveAddress].draining)
            revert GatewaysAlreadyDraining();

        gateways[_enclaveAddress].draining = true;
        gateways[_enclaveAddress].drainStartTime = block.timestamp;

        emit GatewayDrained(_enclaveAddress);
    }

    function _deregisterGateway(
        address _enclaveAddress
    ) internal {
        if (!gateways[_enclaveAddress].draining)
            revert GatewaysNotDraining();

        if(block.timestamp <= gateways[_enclaveAddress].drainStartTime + DRAINING_TIME_DURATION)
            revert GatewaysDrainPending();


        _removeStake(_enclaveAddress, gateways[_enclaveAddress].stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete gateways[_enclaveAddress];

        emit GatewayDeregistered(_enclaveAddress);
    }

    function _reviveGateway(address _enclaveAddress) internal {
        if (!gateways[_enclaveAddress].draining)
            revert GatewaysAlreadyRevived();
        gateways[_enclaveAddress].draining = false;
        gateways[_enclaveAddress].drainStartTime = 0;

        emit GatewayRevived(_enclaveAddress);
    }

    function _addGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        _addStake(_enclaveAddress, _amount);
    }

    function _removeGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        if (!gateways[_enclaveAddress].draining)
            revert GatewaysNotDraining();

        if(block.timestamp <= gateways[_enclaveAddress].drainStartTime + DRAINING_TIME_DURATION)
            revert GatewaysDrainPending();

        _removeStake(_enclaveAddress, _amount);
    }

    function _addChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyAddChainsSign(_signature, _chainIds, _signTimestampInMs, _enclaveAddress);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(_chainIds[index], _enclaveAddress);
        }
    }

    function _verifyAddChainsSign(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > (_signTimestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                ADD_CHAINS_TYPEHASH,
                keccak256(abi.encodePacked(_chainIds)),
                _signTimestampInMs
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveAddress)
            revert GatewaysInvalidSigner();

        _allowOnlyVerified(signer);
    }

    function _addChain(
        uint256 _chainId,
        address _enclaveAddress
    ) internal {
        if(requestChains[_chainId].contractAddress == address(0))
            revert GatewaysUnsupportedChain();

        uint256[] memory chainIdList = gateways[_enclaveAddress].chainIds;
        for (uint256 index = 0; index < chainIdList.length; index++) {
            if(chainIdList[index] == _chainId)
                revert GatewaysChainAlreadyExists(_chainId);
        }
        gateways[_enclaveAddress].chainIds.push(_chainId);

        emit ChainAdded(_enclaveAddress, _chainId);
    }

    function _removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyRemoveChainsSign(_signature, _chainIds, _signTimestampInMs, _enclaveAddress);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(_chainIds[index], _enclaveAddress);
        }
    }

    function _verifyRemoveChainsSign(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > (_signTimestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REMOVE_CHAINS_TYPEHASH,
                keccak256(abi.encodePacked(_chainIds)),
                _signTimestampInMs
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveAddress)
            revert GatewaysInvalidSigner();

        _allowOnlyVerified(signer);
    }

    function _removeChain(
        uint256 _chainId,
        address _enclaveAddress
    ) internal {
        uint256[] memory chainIdList = gateways[_enclaveAddress].chainIds;
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
            gateways[_enclaveAddress].chainIds[index] = gateways[_enclaveAddress].chainIds[len - 1];

        gateways[_enclaveAddress].chainIds.pop();

        emit ChainRemoved(_enclaveAddress, _chainId);
    }

    function _addStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        gateways[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        TOKEN.safeTransferFrom(gateways[_enclaveAddress].owner, address(this), _amount);

        emit GatewayStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        gateways[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        TOKEN.safeTransfer(gateways[_enclaveAddress].owner, _amount);

        emit GatewayStakeRemoved(_enclaveAddress, _amount);
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
        uint256 _signTimestampInMs,
        address _gateway
    ) internal {
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert GatewaysJobRelayTimeOver();
        if(relayJobs[_jobId].isResourceUnavailable)
            revert GatewaysJobResourceUnavailable();
        if(relayJobs[_jobId].execStartTime != 0)
            revert GatewaysJobAlreadyRelayed();
        if(_sequenceId != relayJobs[_jobId].sequenceId + 1)
            revert GatewaysInvalidRelaySequenceId();

        uint256 reqChainId = _jobId >> 192;
        if(requestChains[reqChainId].contractAddress == address(0))
            revert GatewaysUnsupportedChain();

        // signature check
        address enclaveAddress = _verifyRelaySign(_signature, _jobId, _codehash, _codeInputs, _deadline,
                                                  _jobRequestTimestamp, _sequenceId, _jobOwner, _signTimestampInMs);

        // reserve execution fee from gateway
        uint256 usdcDeposit = _deadline * EXECUTION_FEE_PER_MS;
        TOKEN_USDC.safeTransferFrom(_gateway, address(this), usdcDeposit);

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
        (uint256 execJobId, uint8 errorCode) = jobMgr.createJob(_codehash, _codeInputs, _deadline);
        if (errorCode == 1) {
            // Resource unavailable
            relayJobs[_jobId].isResourceUnavailable = true;
            return;
        }

        relayJobs[_jobId].execStartTime = block.timestamp;
        relayJobs[_jobId].jobOwner = _jobOwner;
        relayJobs[_jobId].usdcDeposit = _usdcDeposit;
        relayJobs[_jobId].sequenceId = _sequenceId;
        relayJobs[_jobId].gateway = _gateway;
        execJobs[execJobId] = _jobId;
        emit JobCreated(_jobId, execJobId, _jobOwner, _gateway);
    }

    function _verifyRelaySign(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,  // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint256 _signTimestampInMs
    ) internal view returns (address) {
        if (block.timestamp > (_signTimestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

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
                _signTimestampInMs
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
        return signer;
    }

    function _reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestampInMs,
        address _gateway
    ) internal {
        // time check will be done in the gateway enclaves and based on the algo, a new gateway will be selected
        if(block.timestamp > _jobRequestTimestamp + RELAY_BUFFER_TIME)
            revert GatewaysJobRelayTimeOver();

        if(relayJobs[_jobId].execStartTime != 0)
            revert GatewaysJobAlreadyRelayed();
        if(relayJobs[_jobId].isResourceUnavailable)
            revert GatewaysJobResourceUnavailable();
        if(_sequenceId != relayJobs[_jobId].sequenceId + 1 || _sequenceId > 2)
            revert GatewaysInvalidRelaySequenceId();
        relayJobs[_jobId].sequenceId = _sequenceId;

        // signature check
        address enclaveAddress = _verifyReassignGatewaySign(_signature, _jobId, _gatewayOld, _sequenceId, _jobRequestTimestamp, _signTimestampInMs);

        // slash old gateway
        _slashOnReassignGateway(_sequenceId, _gatewayOld, enclaveAddress, _jobOwner);

        emit GatewayReassigned(_jobId, _gatewayOld, _gateway, _sequenceId);
    }

    function _verifyReassignGatewaySign(
        bytes memory _signature,
        uint256 _jobId,
        address _gatewayOld,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        uint256 _signTimestampInMs
    ) internal view returns (address) {
        if (block.timestamp > (_signTimestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REASSIGN_GATEWAY_TYPEHASH,
                _jobId,
                _gatewayOld,
                _sequenceId,
                _jobRequestTimestamp,
                _signTimestampInMs
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
        return signer;
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
        TOKEN.safeTransfer(gateways[_reporterGateway].owner, REASSIGN_COMP_FOR_REPORTER_GATEWAY);

        if (_sequenceId == 1) {
            // if sequenceId = 1, keep the comp in payment pool
            TOKEN.safeTransfer(paymentPool, totalComp - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        } else {
            // if sequenceId = 2, transfer comp to jobOwner
            TOKEN.safeTransfer(_jobOwner, totalComp - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
        }
    }
    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    function registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        uint256 _signTimestampInMs
    ) external {
        _registerGateway(_attestationSignature, _attestation, _chainIds, _signature, _stakeAmount, _signTimestampInMs, _msgSender());
    }

    function deregisterGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _deregisterGateway(_enclaveAddress);
    }

    function drainGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _drainGateway(_enclaveAddress);
    }

    function reviveGateway(address _enclaveAddress) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _reviveGateway(_enclaveAddress);
    }

    function addGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _addGatewayStake(_enclaveAddress, _amount);
    }

    function removeGatewayStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _removeGatewayStake(_enclaveAddress, _amount);
    }

    function addChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _addChains(_signature, _chainIds, _signTimestampInMs, _enclaveAddress);
    }

    function removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _signTimestampInMs,
        address _enclaveAddress
    ) external isValidGatewayOwner(_enclaveAddress, _msgSender()) {
        _removeChains(_signature, _chainIds, _signTimestampInMs, _enclaveAddress);
    }

    function isChainSupported(
        uint256 _reqChainId
    ) external view returns (bool) {
        return (requestChains[_reqChainId].contractAddress != address(0));
    }

    function getGatewayChainIds(
        address _enclaveAddress
    ) external view returns (uint256[] memory) {
        return gateways[_enclaveAddress].chainIds;
    }

    function relayJob(
        bytes memory _signature,
        uint256 _jobId,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline,  // in milliseconds
        uint256 _jobRequestTimestamp,
        uint8 _sequenceId,
        address _jobOwner,
        uint256 _signTimestampInMs
    ) external {
        _relayJob(_signature, _jobId, _codehash, _codeInputs, _deadline, _jobRequestTimestamp, _sequenceId, _jobOwner, _signTimestampInMs, _msgSender());
    }

    function reassignGatewayRelay(
        address _gatewayOld,
        uint256 _jobId,
        bytes memory _signature,
        uint8 _sequenceId,
        uint256 _jobRequestTimestamp,
        address _jobOwner,
        uint256 _signTimestampInMs
    ) external {
        _reassignGatewayRelay(_gatewayOld, _jobId, _signature, _sequenceId, _jobRequestTimestamp, _jobOwner, _signTimestampInMs, _msgSender());
    }



    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

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

        TOKEN_USDC.safeTransfer(gateways[gateway].owner, usdcDeposit - _totalTime * EXECUTION_FEE_PER_MS);
        emit JobResponded(jobId, _output, _totalTime, _errorCode);
    }

    function _oysterFailureCall(uint256 _execJobId, uint256 _slashAmount) internal {
        uint jobId = execJobs[_execJobId];
        address gateway = relayJobs[jobId].gateway;
        uint256 usdcDeposit = relayJobs[jobId].usdcDeposit;
        address jobOwner = relayJobs[jobId].jobOwner;
        delete execJobs[_execJobId];
        delete relayJobs[jobId];

        TOKEN_USDC.safeTransfer(gateways[gateway].owner, usdcDeposit);
        TOKEN.safeTransfer(jobOwner, _slashAmount - SLASH_COMP_FOR_GATEWAY);
        TOKEN.safeTransfer(gateways[gateway].owner, SLASH_COMP_FOR_GATEWAY);
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
