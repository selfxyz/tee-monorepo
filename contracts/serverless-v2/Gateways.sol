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
        uint256 _deregisterOrUnstakeTimeout
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert GatewaysZeroAddressToken();
        TOKEN = _token;
        DEREGISTER_OR_UNSTAKE_TIMEOUT = _deregisterOrUnstakeTimeout;
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

    //-------------------------------- Gateway start --------------------------------//


    struct RequestChain {
        address contractAddress;
        string httpRpcUrl;
        string wsRpcUrl;
    }

    mapping(uint256 => RequestChain) public requestChains;

    struct Gateway {
        address enclaveKey;
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
        keccak256("Register(address gateway,uint256[] chainIds)");

    event GatewayRegistered(
        address indexed gateway,
        address indexed enclaveKey,
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
        uint256 _stakeAmount
    ) internal {
        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        address gateway = _msgSender();
        address enclaveKey = _pubKeyToAddress(_attestation.enclavePubKey);
        // signature check
        _verifySign(_chainIds, _signature, enclaveKey);
        
        if(gateways[gateway].enclaveKey != address(0))
            revert GatewaysGatewayAlreadyExists();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            if(requestChains[_chainIds[index]].contractAddress == address(0))
                revert GatewaysUnsupportedChain();
        }

        // check missing for validating chainIds array for multiple same chainIds

        _register(gateway, enclaveKey, _chainIds);

        _addStake(gateway, _stakeAmount);
    }

    function _verifySign(
        uint256[] memory _chainIds,
        bytes memory _signature,
        address _enclaveKey
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _msgSender(),
                keccak256(abi.encodePacked(_chainIds))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveKey)
            revert GatewaysInvalidSigner();
    }

    function _register(
        address _gateway,
        address _enclaveKey,
        uint256[] memory _chainIds
    ) internal {
        gateways[_gateway].enclaveKey = _enclaveKey;
        gateways[_gateway].chainIds = _chainIds;
        gateways[_gateway].status = true;

        emit GatewayRegistered(_gateway, _enclaveKey, _chainIds);
    }

    function _deregisterGateway() internal {
        address gateway = _msgSender();
        _isValidGateway(gateway);
        if(gateways[gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();

        gateways[gateway].status = false;
        gateways[gateway].deregisterStartTime = block.timestamp;

        emit GatewayDeregistered(gateway);
    }

    function _completeDeregistration() internal {
        address gateway = _msgSender();
        _isValidGateway(gateway);
        if(gateways[gateway].deregisterStartTime == 0)
            revert GatewaysDeregisterNotInitiated();
        if(block.timestamp <= gateways[gateway].deregisterStartTime + DEREGISTER_OR_UNSTAKE_TIMEOUT)
            revert GatewaysDeregisterTimePending();

        _removeStake(gateway, gateways[gateway].stakeAmount);
        
        _revokeEnclaveKey(gateways[gateway].enclaveKey);
        delete gateways[gateway];

        emit GatewayDeregisterCompleted(gateway);
    }

    function _addGatewayStake(
        uint256 _amount
    ) internal {
        address gateway = _msgSender();
        _isValidGateway(gateway);

        _addStake(gateway, _amount);
    }

    // TODO: check if the gateway is assigned some job before full stake removal
    function _removeGatewayStake() internal {
        address gateway = _msgSender();
        _isValidGateway(gateway);

        if(gateways[gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();
        if(gateways[gateway].unstakeStartTime > 0)
            revert GatewaysStakeRemoveAlreadyInitiated();

        gateways[gateway].status = false;
        gateways[gateway].unstakeStartTime = block.timestamp;

        emit GatewayStakeRemoveInitiated(gateway);
    }

    function _completeRemoveGatewayStake(
        uint256 _amount
    ) internal {
        address gateway = _msgSender();
        _isValidGateway(gateway);
        if(gateways[gateway].status)
            revert GatewaysInvalidStatus();
        if(gateways[gateway].deregisterStartTime > 0)
            revert GatewaysDeregisterAlreadyInitiated();
        if(block.timestamp <= gateways[gateway].unstakeStartTime + DEREGISTER_OR_UNSTAKE_TIMEOUT)
            revert GatewaysUnstakeTimePending();

        _amount = _amount < gateways[gateway].stakeAmount ? _amount : gateways[gateway].stakeAmount;
        if(_amount == 0)
            revert GatewaysInvalidAmount();

        gateways[gateway].unstakeStartTime = 0;
        gateways[gateway].status = true;

        _removeStake(gateway, _amount);
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
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();

        address gateway = _msgSender();
        _isValidGateway(gateway);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(_chainIds[index], gateway);
        }
    }

    function _removeChains(
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert GatewaysEmptyRequestedChains();
        
        address gateway = _msgSender();
        _isValidGateway(gateway);

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(_chainIds[index], gateway);
        }
    }

    function _addChain(
        uint256 _chainId,
        address gateway
    ) internal {
        if(requestChains[_chainId].contractAddress == address(0))
            revert GatewaysUnsupportedChain();

        uint256[] memory chainIdList = gateways[gateway].chainIds;
        for (uint256 index = 0; index < chainIdList.length; index++) {
            if(chainIdList[index] == _chainId)
                revert GatewaysChainAlreadyExists(_chainId);
        }
        gateways[gateway].chainIds.push(_chainId);

        emit ChainAdded(gateway, _chainId);
    }

    function _removeChain(
        uint256 _chainId,
        address gateway
    ) internal {
        uint256[] memory chainIdList = gateways[gateway].chainIds;
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
            gateways[gateway].chainIds[index] = gateways[gateway].chainIds[len - 1];

        gateways[gateway].chainIds.pop();

        emit ChainRemoved(gateway, _chainId);
    }

    function _isValidGateway(
        address _gateway
    ) internal view {
        if(gateways[_gateway].enclaveKey == address(0))
            revert GatewaysInvalidGateway();
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
        uint256 _stakeAmount
    ) external {
        _registerGateway(_attestationSignature, _attestation, _chainIds, _signature, _stakeAmount);
    }

    function deregisterGateway() external {
        _deregisterGateway();
    }

    function completeDeregistration() external {
        _completeDeregistration();
    }

    function addGatewayStake(
        uint256 _amount
    ) external {
        _addGatewayStake(_amount);
    }

    function removeGatewayStake() external {
        _removeGatewayStake();
    }

    function completeRemoveGatewayStake(
        uint256 _amount
    ) external {
        _completeRemoveGatewayStake(_amount);
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
        uint256[] memory _chainIds
    ) external {
        _addChains(_chainIds);
    }

    function removeChains(
        uint256[] memory _chainIds
    ) external {
        _removeChains(_chainIds);
    }

    function isChainSupported(
        uint256 _reqChainId
    ) external view returns (bool) {
        return (requestChains[_reqChainId].contractAddress != address(0));
    }

    function allowOnlyVerified(
        address _enclaveKey,
        address _gateway
    ) external view {
        _allowOnlyVerified(_enclaveKey);
        if(_enclaveKey != gateways[_gateway].enclaveKey)
            revert GatewaysInvalidSigner();
    }

    function getGatewayChainIds(
        address _gateway
    ) external view returns (uint256[] memory) {
        return gateways[_gateway].chainIds;
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

}
