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

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _deregisterOrUnstakeTimeout,
        uint256 _reassignCompForReporterGateway,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert GatewaysZeroAddressToken();
        TOKEN = _token;
        DEREGISTER_OR_UNSTAKE_TIMEOUT = _deregisterOrUnstakeTimeout;

        REASSIGN_COMP_FOR_REPORTER_GATEWAY = _reassignCompForReporterGateway;
        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
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
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert GatewaysZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

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

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

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

    // gateway => Gateway
    mapping(address => Gateway) public gateways;

    bytes32 private constant DOMAIN_SEPARATOR = 
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Gateways"),
                keccak256("1")
            )
        );
    
    bytes32 private constant REGISTER_TYPEHASH = 
        keccak256("Register(address gateway,uint256[] chainIds,uint256 timestampInMs)");
    bytes32 private constant ADD_CHAINS_TYPEHASH = 
        keccak256("AddChains(address gateway,uint256[] chainIds,uint256 timestampInMs)");
    bytes32 private constant REMOVE_CHAINS_TYPEHASH = 
        keccak256("RemoveChains(address gateway,uint256[] chainIds,uint256 timestampInMs)");

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

    error GatewaysInvalidSigner();
    error GatewaysGatewayAlreadyExists();
    error GatewaysUnsupportedChain();
    error GatewaysSignatureTooOld();
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

    //-------------------------------- internal functions start ----------------------------------//

    function _registerGateway(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount,
        uint256 _timestampInMs,
        address _gateway
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifyRegisterSign(_gateway, _chainIds, _timestampInMs, _signature, enclaveAddress);
        
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
        uint256 _timestampInMs,
        bytes memory _signature,
        address _enclaveAddress
    ) internal view {
        if (block.timestamp > (_timestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds)),
                _timestampInMs
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
        uint256 _timestampInMs,
        address _gateway
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyAddChainsSign(_signature, _gateway, _chainIds, _timestampInMs);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(_chainIds[index], _gateway);
        }
    }

    function _verifyAddChainsSign(
        bytes memory _signature,
        address _gateway,
        uint256[] memory _chainIds,
        uint256 _timestampInMs
    ) internal view {
        if (block.timestamp > (_timestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                ADD_CHAINS_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds)),
                _timestampInMs
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
        uint256 _timestampInMs,
        address _gateway
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        _verifyRemoveChainsSign(_signature, _gateway, _chainIds, _timestampInMs);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(_chainIds[index], _gateway);
        }
    }

    function _verifyRemoveChainsSign(
        bytes memory _signature,
        address _gateway,
        uint256[] memory _chainIds,
        uint256 _timestampInMs
    ) internal view {
        if (block.timestamp > (_timestampInMs / 1000) + ATTESTATION_MAX_AGE)
            revert GatewaysSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REMOVE_CHAINS_TYPEHASH,
                _gateway,
                keccak256(abi.encodePacked(_chainIds)),
                _timestampInMs
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
        uint256 _stakeAmount,
        uint256 _timestampInMs
    ) external {
        _registerGateway(_attestationSignature, _attestation, _chainIds, _signature, _stakeAmount, _timestampInMs, _msgSender());
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
        uint256[] memory _chainIds,
        uint256 _timestampInMs
    ) external isValidGateway(_msgSender()) {
        _addChains(_signature, _chainIds, _timestampInMs, _msgSender());
    }

    function removeChains(
        bytes memory _signature,
        uint256[] memory _chainIds,
        uint256 _timestampInMs
    ) external isValidGateway(_msgSender()) {
        _removeChains(_signature, _chainIds, _timestampInMs, _msgSender());
    }

    function isChainSupported(
        uint256 _reqChainId
    ) external view returns (bool) {
        return (requestChains[_reqChainId].contractAddress != address(0));
    }

    function allowOnlyVerified(
        address _enclaveAddress,
        address _gateway
    ) external view {
        _allowOnlyVerified(_enclaveAddress);
        if(_enclaveAddress != gateways[_gateway].enclaveAddress)
            revert GatewaysInvalidSigner();
    }

    function getGatewayChainIds(
        address _gateway
    ) external view returns (uint256[] memory) {
        return gateways[_gateway].chainIds;
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

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

        // if sequenceId = 1, transfer comp to common pool(jobs contract)
        // if sequenceId = 2, transfer comp to jobOwner
        TOKEN.safeTransfer(_sequenceId == 1 ? _msgSender() : _jobOwner, totalComp - REASSIGN_COMP_FOR_REPORTER_GATEWAY);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //------------------------------- external functions start ---------------------------------//

    function slashOnReassignGateway(
        uint8 _sequenceId,
        address _oldGateway,
        address _reporterGateway,
        address _jobOwner
    ) external onlyRole(JOBS_ROLE) {
        _slashOnReassignGateway(_sequenceId, _oldGateway, _reporterGateway, _jobOwner);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
