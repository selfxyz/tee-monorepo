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

contract CommonChainGateways is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, 
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error ZeroAddressToken();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _timeoutDuration
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert ZeroAddressToken();
        TOKEN = _token;
        TIMEOUT_DURATION = _timeoutDuration;
    }

    //-------------------------------- Overrides start --------------------------------//

    error ZeroAddressAdmin();

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

    function __CommonChainGateways_init(
        address _admin,
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert ZeroAddressAdmin();

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
    uint256 public immutable TIMEOUT_DURATION;

    //-------------------------------- Gateway start --------------------------------//


    struct RequestChain {
        address contractAddress;
        string rpcUrl;
    }

    mapping(uint256 => RequestChain) public requestChains;

    struct Gateway {
        address operator;
        uint256[] chainIds;
        uint256 stakeAmount;
        uint256 deregisterStartTime;
        bool status;
        uint256 unstakeStartTime;
    }

    // enclaveAddress => Gateway
    mapping(address => Gateway) public gateways;

    error InvalidGatewayOperator();

    modifier onlyGatewayOperator(bytes memory _enclavePubKey) {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gateways[enclaveKey].operator != _msgSender())
            revert InvalidGatewayOperator();
        _;
    }

    event GatewayRegistered(
        address indexed enclaveKey,
        address indexed operator,
        uint256[] chainIds
    );

    event GatewayDeregistered(address indexed enclaveKey);

    event GatewayDeregisterCompleted(address indexed enclaveKey);

    event GatewayStakeAdded(
        address indexed enclaveKey,
        uint256 addedAmount,
        uint256 totalAmount
    );

    event GatewayStakeRemoveInitiated(address indexed enclaveKey);

    event GatewayStakeRemoved(
        address indexed enclaveKey,
        uint256 removedAmount,
        uint256 totalAmount
    );

    event ChainAddedGlobal(
        uint256 chainId,
        address contractAddress,
        string rpcUrl
    );

    event ChainRemovedGlobal(
        uint256 chainId
    );

    event ChainAdded(
        address indexed enclaveKey,
        uint256 chainId
    );

    event ChainRemoved(
        address indexed enclaveKey,
        uint256 chainId
    );

    error GatewayAlreadyExists();
    error UnsupportedChain();
    error InvalidEnclaveKey();
    error InvalidStatus();
    error DeregisterTimePending();
    error GatewayDeregisterAlreadyInitiated();
    error GatewayStakeRemoveAlreadyInitiated();
    error UnstakeTimePending();
    error InvalidAmount();
    error InvalidLength();
    error EmptyRequestedChains();
    error ChainAlreadyExists(uint256 chainId);
    error EmptyChainlist();
    error ChainNotFound(uint256 chainId);

    //-------------------------------- internal functions start ----------------------------------//

    function _registerGateway(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount
    ) internal {
        // attestation verification
        _verifyEnclaveKey(
            _attestation, 
            IAttestationVerifier.Attestation(_enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds)
        );

        // signature check
        _verifySign(_chainIds, _signature);

        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _stakeAmount);
        
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gateways[enclaveKey].operator != address(0))
            revert GatewayAlreadyExists();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            if(requestChains[_chainIds[index]].contractAddress == address(0))
                revert UnsupportedChain();
        }

        // check missing for validating chainIds array for multiple same chainIds
        
        gateways[enclaveKey] = Gateway({
            operator: _msgSender(),
            chainIds: _chainIds,
            stakeAmount: _stakeAmount,
            deregisterStartTime: 0,
            status: true,
            unstakeStartTime: 0
        });

        emit GatewayRegistered(enclaveKey, _msgSender(), _chainIds);
    }

    function _verifySign(
        uint256[] memory _chainIds,
        bytes memory _signature
    ) internal view {
        bytes32 digest = keccak256(abi.encodePacked(_chainIds));
        address signer = digest.recover(_signature);

        _allowOnlyVerified(signer);
    }

    function _deregisterGateway(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gateways[enclaveKey].operator == address(0))
            revert InvalidEnclaveKey();
        // TODO: cannot call deregister initiate again
        if(gateways[enclaveKey].deregisterStartTime > 0)
            revert GatewayDeregisterAlreadyInitiated();

        gateways[enclaveKey].status = false;
        gateways[enclaveKey].deregisterStartTime = block.timestamp;

        emit GatewayDeregistered(enclaveKey);
    }

    function _completeDegistration(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gateways[enclaveKey].status)
            revert InvalidStatus();
        if(block.timestamp <= gateways[enclaveKey].deregisterStartTime + TIMEOUT_DURATION)
            revert DeregisterTimePending();

        // TODO: return stake amount
        TOKEN.safeTransfer(_msgSender(), gateways[enclaveKey].stakeAmount);

        delete gateways[enclaveKey];
        _revokeEnclaveKey(_enclavePubKey);

        emit GatewayDeregisterCompleted(enclaveKey);
    }

    function _addGatewayStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        // transfer stake
        TOKEN.safeTransferFrom(_msgSender(), address(this), _amount);

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        gateways[enclaveKey].stakeAmount += _amount;

        emit GatewayStakeAdded(enclaveKey, _amount, gateways[enclaveKey].stakeAmount);
    }

    // TODO: check if the gateway is assigned some job before full stake removal
    function _removeGatewayStake(
        bytes memory _enclavePubKey
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        // TODO: cannot remove stake if deregister initiated already
        if(gateways[enclaveKey].deregisterStartTime > 0)
            revert GatewayDeregisterAlreadyInitiated();
        if(gateways[enclaveKey].unstakeStartTime > 0)
            revert GatewayStakeRemoveAlreadyInitiated();

        gateways[enclaveKey].status = false;
        gateways[enclaveKey].unstakeStartTime = block.timestamp;

        emit GatewayStakeRemoveInitiated(enclaveKey);
    }

    // TODO: if initiated unstake, and then deregister....then complete unstake shouldn't be allowed
    function _completeRemoveGatewayStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        if(gateways[enclaveKey].status)
            revert InvalidStatus();
        if(gateways[enclaveKey].deregisterStartTime > 0)
            revert GatewayDeregisterAlreadyInitiated();
        if(block.timestamp <= gateways[enclaveKey].unstakeStartTime + TIMEOUT_DURATION)
            revert UnstakeTimePending();

        _amount = _amount < gateways[enclaveKey].stakeAmount ? _amount : gateways[enclaveKey].stakeAmount;
        if(_amount == 0)
            revert InvalidAmount();

        // transfer stake
        TOKEN.safeTransfer(_msgSender(), _amount);

        gateways[enclaveKey].stakeAmount -= _amount;
        gateways[enclaveKey].unstakeStartTime = 0;
        // update status only if deregistration hasn't been started
        if(gateways[enclaveKey].deregisterStartTime == 0)
            gateways[enclaveKey].status = true;

        emit GatewayStakeRemoved(enclaveKey, _amount, gateways[enclaveKey].stakeAmount);
    }

    function _addChainGlobal(
        uint256[] memory _chainIds,
        RequestChain[] memory _requestChains
    ) internal {
        if(_chainIds.length == 0 || _chainIds.length != _requestChains.length)
            revert InvalidLength();
        for (uint256 index = 0; index < _requestChains.length; index++) {
            RequestChain memory reqChain = _requestChains[index];
            uint256 chainId = _chainIds[index];
            requestChains[chainId] = reqChain;

            emit ChainAddedGlobal(chainId, reqChain.contractAddress, reqChain.rpcUrl);
        }
    }

    function _removeChainGlobal(
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert InvalidLength();
        for (uint256 index = 0; index < _chainIds.length; index++) {
            uint256 chainId = _chainIds[index];
            delete requestChains[chainId];

            emit ChainRemovedGlobal(chainId);
        }
    }

    function _addChains(
        bytes memory _enclavePubKey,
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert EmptyRequestedChains();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _addChain(
                _enclavePubKey, 
                _chainIds[index]
            );
        }
    }

    function _removeChains(
        bytes memory _enclavePubKey,
        uint256[] memory _chainIds
    ) internal {
        if(_chainIds.length == 0)
            revert EmptyRequestedChains();

        for (uint256 index = 0; index < _chainIds.length; index++) {
            _removeChain(
                _enclavePubKey, 
                _chainIds[index]
            );
        }
    }

    function _addChain(
        bytes memory _enclavePubKey,
        uint256 _chainId
    ) internal {
        if(requestChains[_chainId].contractAddress == address(0))
            revert UnsupportedChain();

        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        uint256[] memory chainIdList = gateways[enclaveKey].chainIds;
        for (uint256 index = 0; index < chainIdList.length; index++) {
            if(chainIdList[index] == _chainId)
                revert ChainAlreadyExists(_chainId);
        }
        gateways[enclaveKey].chainIds.push(_chainId);

        emit ChainAdded(enclaveKey, _chainId);
    }

    function _removeChain(
        bytes memory _enclavePubKey,
        uint256 _chainId
    ) internal {
        address enclaveKey = _pubKeyToAddress(_enclavePubKey);
        uint256[] memory chainIdList = gateways[enclaveKey].chainIds;
        uint256 len = chainIdList.length;
        if(len == 0)
            revert EmptyChainlist();

        uint256 index = 0;
        for (; index < len; index++) {
            if (chainIdList[index] == _chainId) 
                break;
        }

        if(index != len)
            revert ChainNotFound(_chainId);
        if (index != len - 1)
            gateways[enclaveKey].chainIds[index] = gateways[enclaveKey].chainIds[len - 1];

        gateways[enclaveKey].chainIds.pop();

        emit ChainRemoved(enclaveKey, _chainId);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start --------------------------------//

    function registerGateway(
        bytes memory _attestation,
        bytes memory _enclavePubKey,
        bytes memory _PCR0,
        bytes memory _PCR1,
        bytes memory _PCR2,
        uint256 _timestampInMilliseconds,
        uint256[] memory _chainIds,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerGateway(_attestation, _enclavePubKey, _PCR0, _PCR1, _PCR2, _timestampInMilliseconds, _chainIds, _signature, _stakeAmount);
    }

    function deregisterGateway(
        bytes memory _enclavePubKey
    ) external onlyGatewayOperator(_enclavePubKey) {
        _deregisterGateway(_enclavePubKey);
    }

    function completeDegistration(
        bytes memory _enclavePubKey
    ) external onlyGatewayOperator(_enclavePubKey) {
        _completeDegistration(_enclavePubKey);
    }

    function addGatewayStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) external onlyGatewayOperator(_enclavePubKey) {
        _addGatewayStake(_enclavePubKey, _amount);
    }

    function removeGatewayStake(
        bytes memory _enclavePubKey
    ) external onlyGatewayOperator(_enclavePubKey) {
        _removeGatewayStake(_enclavePubKey);
    }

    function completeRemoveGatewayStake(
        bytes memory _enclavePubKey,
        uint256 _amount
    ) external onlyGatewayOperator(_enclavePubKey) {
        _completeRemoveGatewayStake(_enclavePubKey, _amount);
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
        bytes memory _enclavePubKey,
        uint256[] memory _chainIds
    ) external onlyGatewayOperator(_enclavePubKey) {
        _addChains(_enclavePubKey, _chainIds);
    }

    function removeChains(
        bytes memory _enclavePubKey,
        uint256[] memory _chainIds
    ) external onlyGatewayOperator(_enclavePubKey) {
        _removeChains(_enclavePubKey, _chainIds);
    }

    function isChainSupported(
        uint256 _reqChainId
    ) external view returns (bool) {
        return (requestChains[_reqChainId].contractAddress != address(0));
    }

    function allowOnlyVerified(address _key) external view {
        _allowOnlyVerified(_key);
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- Gateway end --------------------------------//

}
