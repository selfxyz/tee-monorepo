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
import "./tree/TreeUpgradeable.sol";
import "../interfaces/IAttestationVerifier.sol";

contract Executors is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable,
    UUPSUpgradeable, // public upgrade
    AttestationAutherUpgradeable,
    TreeUpgradeable
{
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    error ExecutorsZeroAddressToken();
    error ExecutorsZeroMinStakeAmount();

    /// @custom:oz-upgrades-unsafe-allow constructor
    // initializes the logic contract without any admins
    // safeguard against takeover of the logic contract
    constructor(
        IAttestationVerifier attestationVerifier,
        uint256 maxAge,
        IERC20 _token,
        uint256 _minStakeAmount,
        uint256 _slashPercentInBips,
        uint256 _slashMaxBips
    ) AttestationAutherUpgradeable(attestationVerifier, maxAge) {
        _disableInitializers();

        if(address(_token) == address(0))
            revert ExecutorsZeroAddressToken();
        if(_minStakeAmount == 0)
            revert ExecutorsZeroMinStakeAmount();

        TOKEN = _token;
        MIN_STAKE_AMOUNT = _minStakeAmount;

        SLASH_PERCENT_IN_BIPS = _slashPercentInBips;
        SLASH_MAX_BIPS = _slashMaxBips;
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

    error ExecutorsZeroAddressAdmin();

    function initialize(
        address _admin,
        EnclaveImage[] memory _images
    ) public initializer {
        if(_admin == address(0))
            revert ExecutorsZeroAddressAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();
        __AttestationAuther_init_unchained(_images);
        __TreeUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    //-------------------------------- Initializer end --------------------------------//

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    IERC20 public immutable TOKEN;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable MIN_STAKE_AMOUNT;

    /// @notice an integer in the range 0-10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_PERCENT_IN_BIPS;

    /// @notice expected to be 10^6
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    uint256 public immutable SLASH_MAX_BIPS;

    /// @notice executor stake amount will be divided by 10^18 before adding to the tree
    uint256 public constant STAKE_ADJUSTMENT_FACTOR = 1e18;

    bytes32 public constant JOBS_ROLE = keccak256("JOBS_ROLE");

    //-------------------------------- Executor start --------------------------------//

    modifier isValidExecutorOwner(
        address _enclaveAddress,
        address _owner
    ) {
        if (executors[_enclaveAddress].owner != _owner)
            revert ExecutorsInvalidOwner();
        _;
    }

    struct Executor {
        address owner;
        uint256 jobCapacity;
        uint256 activeJobs;
        uint256 stakeAmount;
        bool draining;
    }

    // enclaveAddress => Execution node details
    mapping(address => Executor) public executors;

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.Executors"),
                keccak256("1")
            )
        );

    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(address owner,uint256 jobCapacity,uint256 signTimestamp)");

    event ExecutorRegistered(
        address indexed enclaveAddress,
        address indexed owner,
        uint256 jobCapacity
    );

    event ExecutorDeregistered(address indexed enclaveAddress);

    event ExecutorDrained(
        address indexed enclaveAddress
    );
    event ExecutorRevived(
        address indexed enclaveAddress
    );

    event ExecutorStakeAdded(
        address indexed enclaveAddress,
        uint256 addedAmount
    );

    event ExecutorStakeRemoved(
        address indexed enclaveAddress,
        uint256 removedAmount
    );

    error ExecutorsSignatureTooOld();
    error ExecutorsInvalidSigner();
    error ExecutorsExecutorAlreadyExists();
    error ExecutorsAlreadyDraining();
    error ExecutorsAlreadyRevived();
    error ExecutorsNotDraining();
    error ExecutorsHasPendingJobs();
    error ExecutorsInvalidOwner();

    //-------------------------------- Admin methods start --------------------------------//

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

    //-------------------------------- Admin methods end ----------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _registerExecutor(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount,
        address _owner
    ) internal {
        address enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if(executors[enclaveAddress].owner != address(0))
            revert ExecutorsExecutorAlreadyExists();

        // attestation verification
        _verifyEnclaveKey(_attestationSignature, _attestation);

        // signature check
        _verifySign(enclaveAddress, _owner, _jobCapacity, _signTimestamp, _signature);

        _register(enclaveAddress, _owner, _jobCapacity);

        // add node to the tree if min stake amount deposited
        if(_stakeAmount >= MIN_STAKE_AMOUNT)
            _insert_unchecked(enclaveAddress, uint64(_stakeAmount / STAKE_ADJUSTMENT_FACTOR));

        _addStake(enclaveAddress, _stakeAmount);
    }

    function _verifySign(
        address _enclaveAddress,
        address _owner,
        uint256 _jobCapacity,
        uint256 _signTimestamp,
        bytes memory _signature
    ) internal view {
        if (block.timestamp > _signTimestamp + ATTESTATION_MAX_AGE)
            revert ExecutorsSignatureTooOld();

        bytes32 hashStruct = keccak256(
            abi.encode(
                REGISTER_TYPEHASH,
                _owner,
                _jobCapacity,
                _signTimestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));
        address signer = digest.recover(_signature);

        if(signer != _enclaveAddress)
            revert ExecutorsInvalidSigner();
    }

    function _register(
        address _enclaveAddress,
        address _owner,
        uint256 _jobCapacity
    ) internal {
        executors[_enclaveAddress].jobCapacity = _jobCapacity;
        executors[_enclaveAddress].owner = _owner;

        emit ExecutorRegistered(_enclaveAddress, _owner, _jobCapacity);
    }

    function _drainExecutor(
        address _enclaveAddress
    ) internal {
        if(executors[_enclaveAddress].draining)
            revert ExecutorsAlreadyDraining();

        executors[_enclaveAddress].draining = true;

        // remove node from the tree
        _deleteIfPresent(_enclaveAddress);

        emit ExecutorDrained(_enclaveAddress);
    }

    function _reviveExecutor(
        address _enclaveAddress
    ) internal {
        Executor memory executorNode = executors[_enclaveAddress];
        if(!executorNode.draining)
            revert ExecutorsAlreadyRevived();

        executors[_enclaveAddress].draining = false;

        // insert node in the tree
        if(executorNode.stakeAmount >= MIN_STAKE_AMOUNT &&
            executorNode.activeJobs < executorNode.jobCapacity
        ) {
            _insert_unchecked(_enclaveAddress, uint64(executorNode.stakeAmount / STAKE_ADJUSTMENT_FACTOR));
        }

        emit ExecutorRevived(_enclaveAddress);
    }

    function _deregisterExecutor(
        address _enclaveAddress
    ) internal {
        if(!executors[_enclaveAddress].draining)
            revert ExecutorsNotDraining();
        if(executors[_enclaveAddress].activeJobs != 0)
            revert ExecutorsHasPendingJobs();

        _removeStake(_enclaveAddress, executors[_enclaveAddress].stakeAmount);

        _revokeEnclaveKey(_enclaveAddress);
        delete executors[_enclaveAddress];

        emit ExecutorDeregistered(_enclaveAddress);
    }

    function _addExecutorStake(
        uint256 _amount,
        address _enclaveAddress
    ) internal {
        Executor memory executorNode = executors[_enclaveAddress];
        uint256 updatedStake = executorNode.stakeAmount + _amount;

        if(
            !executorNode.draining &&
            executorNode.activeJobs < executorNode.jobCapacity &&
            updatedStake >= MIN_STAKE_AMOUNT
        ) {
            // if prevStake is less than min stake, then insert node in tree, else update the node value in tree
            _upsert(_enclaveAddress, uint64(updatedStake / STAKE_ADJUSTMENT_FACTOR));
        }

        _addStake(_enclaveAddress, _amount);
    }

    function _removeExecutorStake(
        uint256 _amount,
        address _enclaveAddress
    ) internal {
        if(!executors[_enclaveAddress].draining)
            revert ExecutorsNotDraining();
        if(executors[_enclaveAddress].activeJobs != 0)
            revert ExecutorsHasPendingJobs();

        _removeStake(_enclaveAddress, _amount);
    }

    function _addStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        executors[_enclaveAddress].stakeAmount += _amount;
        // transfer stake
        TOKEN.safeTransferFrom(executors[_enclaveAddress].owner, address(this), _amount);

        emit ExecutorStakeAdded(_enclaveAddress, _amount);
    }

    function _removeStake(
        address _enclaveAddress,
        uint256 _amount
    ) internal {
        executors[_enclaveAddress].stakeAmount -= _amount;
        // transfer stake
        TOKEN.safeTransfer(executors[_enclaveAddress].owner, _amount);

        emit ExecutorStakeRemoved(_enclaveAddress, _amount);
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function registerExecutor(
        bytes memory _attestationSignature,
        IAttestationVerifier.Attestation memory _attestation,
        uint256 _jobCapacity,
        uint256 _signTimestamp,
        bytes memory _signature,
        uint256 _stakeAmount
    ) external {
        _registerExecutor(_attestationSignature, _attestation, _jobCapacity, _signTimestamp, _signature, _stakeAmount, _msgSender());
    }

    function deregisterExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _deregisterExecutor(_enclaveAddress);
    }

    function drainExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _drainExecutor(_enclaveAddress);
    }

    function reviveExecutor(address _enclaveAddress) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _reviveExecutor(_enclaveAddress);
    }

    function addExecutorStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _addExecutorStake(_amount, _enclaveAddress);
    }

    function removeExecutorStake(
        address _enclaveAddress,
        uint256 _amount
    ) external isValidExecutorOwner(_enclaveAddress, _msgSender()) {
        _removeExecutorStake(_amount, _enclaveAddress);
    }

    function allowOnlyVerified(
        address _signer
    ) external view {
        _allowOnlyVerified(_signer);
    }

    //-------------------------------- external functions end ----------------------------------//

    //--------------------------------------- Executor end -----------------------------------------//


    //-------------------------------- JobsContract functions start --------------------------------//

    //-------------------------------- internal functions start ----------------------------------//

    function _selectExecutors(
        uint256 _noOfNodesToSelect
    ) internal returns (address[] memory selectedNodes) {
        selectedNodes = _selectNodes(_noOfNodesToSelect);
        for (uint256 index = 0; index < selectedNodes.length; index++) {
            address enclaveAddress = selectedNodes[index];
            executors[enclaveAddress].activeJobs += 1;

            // if jobCapacity reached then delete from the tree so as to not consider this node in new jobs allocation
            if(executors[enclaveAddress].activeJobs == executors[enclaveAddress].jobCapacity)
                _deleteIfPresent(enclaveAddress);
        }
    }

    function _selectNodes(
        uint256 _noOfNodesToSelect
    ) internal view returns (address[] memory selectedNodes) {
        uint256 randomizer = uint256(keccak256(abi.encode(blockhash(block.number - 1), block.timestamp)));
        selectedNodes = _selectN(randomizer, _noOfNodesToSelect);
        // require(selectedNodes.length != 0, "NO_EXECUTOR_SELECTED");
    }

    function _releaseExecutor(
        address _enclaveAddress
    ) internal {
        if(!executors[_enclaveAddress].draining) {
            // node might have been deleted due to max job capacity reached
            // if stakes are greater than minStakes then update the stakes for executors in tree if it already exists else add with latest stake
            if(executors[_enclaveAddress].stakeAmount >= MIN_STAKE_AMOUNT)
                _upsert(_enclaveAddress, uint64(executors[_enclaveAddress].stakeAmount / STAKE_ADJUSTMENT_FACTOR));
            // remove node from tree if stake falls below min level
            else
                _deleteIfPresent(_enclaveAddress);
        }

        executors[_enclaveAddress].activeJobs -= 1;
    }

    function _slashExecutor(
        address _enclaveAddress,
        address _recipient
    ) internal returns (uint256) {
        uint256 totalComp = executors[_enclaveAddress].stakeAmount * SLASH_PERCENT_IN_BIPS / SLASH_MAX_BIPS;
        executors[_enclaveAddress].stakeAmount -= totalComp;

        TOKEN.safeTransfer(_recipient, totalComp);

        _releaseExecutor(_enclaveAddress);
        return totalComp;
    }

    //-------------------------------- internal functions end ----------------------------------//

    //-------------------------------- external functions start ----------------------------------//

    function selectExecutors(
        uint256 _noOfNodesToSelect
    ) external onlyRole(JOBS_ROLE) returns (address[] memory selectedNodes) {
        return _selectExecutors(_noOfNodesToSelect);
    }

    function releaseExecutor(
        address _enclaveAddress
    ) external onlyRole(JOBS_ROLE) {
        _releaseExecutor(_enclaveAddress);
    }

    function slashExecutor(
        address _enclaveAddress
    ) external onlyRole(JOBS_ROLE) returns (uint256) {
        return _slashExecutor(_enclaveAddress, _msgSender());
    }

    //-------------------------------- external functions end ----------------------------------//

    //-------------------------------- JobsContract functions end --------------------------------//

}
