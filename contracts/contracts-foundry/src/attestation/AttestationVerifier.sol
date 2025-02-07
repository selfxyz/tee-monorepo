// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import "./IAttestationVerifier.sol";

contract AttestationVerifier is
    AccessControl, // RBAC
    IAttestationVerifier // interface
{
    //-------------------------------- Declarations start --------------------------------//

    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    IRiscZeroVerifier public verifier;
    bytes32 public guestId;
    bytes public rootKey;
    uint256 public maxAge;

    // ImageId -> image details
    mapping(bytes32 => bool) public whitelistedImages;
    // enclaveAddress -> ImageId
    mapping(address => bytes32) public verifiedKeys;

    //-------------------------------- Declarations end --------------------------------//

    //-------------------------------- Errors start --------------------------------//

    error AttestationVerifierPubkeyLengthInvalid();
    error AttestationVerifierPCRsInvalid();

    error AttestationVerifierImageNotWhitelisted();
    error AttestationVerifierKeyNotVerified();

    error AttestationVerifierAttestationTooOld();

    //-------------------------------- Errors end --------------------------------//

    //-------------------------------- Events start --------------------------------//

    event AttestationVerifierUpdatedVerifier(IRiscZeroVerifier indexed verifier, IRiscZeroVerifier indexed old);
    event AttestationVerifierUpdatedGuestId(bytes32 indexed guestId, bytes32 indexed old);
    event AttestationVerifierUpdatedPcrs(bytes indexed pcrs, bytes indexed old);
    event AttestationVerifierUpdatedRootKey(bytes indexed rootKey, bytes indexed old);
    event AttestationVerifierUpdatedMaxAge(uint256 maxAge, uint256 old);
    event AttestationVerifierEnclaveImageWhitelisted(bytes32 indexed imageId);
    event AttestationVerifierEnclaveImageRevoked(bytes32 indexed imageId);
    event AttestationVerifierEnclaveKeyVerified(
        address indexed enclaveAddress, bytes32 indexed imageId, bytes indexed enclavePubkey
    );

    //-------------------------------- Events end --------------------------------//

    //-------------------------------- Constructor start --------------------------------//

    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAge,
        bytes32 _imageId
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);

        _updateVerifier(_verifier);
        _updateGuestId(_guestId);
        _updateRootKey(_rootKey);
        _updateMaxAge(_maxAge);

        _whitelistEnclaveImage(_imageId);
    }

    //-------------------------------- Constructor end --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit AttestationVerifierUpdatedVerifier(_verifier, verifier);
        verifier = _verifier;
    }

    function _updateGuestId(bytes32 _guestId) internal {
        emit AttestationVerifierUpdatedGuestId(_guestId, guestId);
        guestId = _guestId;
    }

    function _updateRootKey(bytes memory _rootKey) internal {
        emit AttestationVerifierUpdatedRootKey(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    function _updateMaxAge(uint256 _maxAge) internal {
        emit AttestationVerifierUpdatedMaxAge(_maxAge, maxAge);
        maxAge = _maxAge;
    }

    function _pubKeyToAddress(bytes memory _pubKey) internal pure returns (address) {
        require(_pubKey.length == 64, AttestationVerifierPubkeyLengthInvalid());

        bytes32 _hash = keccak256(_pubKey);
        return address(uint160(uint256(_hash)));
    }

    function _whitelistEnclaveImage(bytes32 _imageId) internal returns (bool) {
        if (whitelistedImages[_imageId]) return false;

        whitelistedImages[_imageId] = true;
        emit AttestationVerifierEnclaveImageWhitelisted(_imageId);

        return true;
    }

    function _revokeEnclaveImage(bytes32 _imageId) internal returns (bool) {
        if (!whitelistedImages[_imageId]) return false;

        delete whitelistedImages[_imageId];
        emit AttestationVerifierEnclaveImageRevoked(_imageId);

        return true;
    }

    function updateVerifier(IRiscZeroVerifier _verifier) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _updateVerifier(_verifier);
    }

    function updateGuestId(bytes32 _guestId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _updateGuestId(_guestId);
    }

    function updateRootKey(bytes calldata _rootKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _updateRootKey(_rootKey);
    }

    function updateMaxAge(uint256 _maxAge) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _updateMaxAge(_maxAge);
    }

    function whitelistEnclaveImage(bytes32 _imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _whitelistEnclaveImage(_imageId);
    }

    function revokeEnclaveImage(bytes32 _imageId) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(_imageId);
    }

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    function _verifyEnclaveKey(bytes memory _signature, Attestation memory _attestation) internal returns (bool) {
        require(
            _attestation.timestampInMilliseconds > block.timestamp * 1000 - maxAge,
            AttestationVerifierAttestationTooOld()
        );
        bytes32 _imageId = _attestation.imageId;
        require(whitelistedImages[_imageId], AttestationVerifierImageNotWhitelisted());

        _verify(_signature, _attestation);

        address _enclaveAddress = _pubKeyToAddress(_attestation.enclavePubKey);
        if (verifiedKeys[_enclaveAddress] != bytes32(0)) return false;

        verifiedKeys[_enclaveAddress] = _imageId;
        emit AttestationVerifierEnclaveKeyVerified(_enclaveAddress, _imageId, _attestation.enclavePubKey);

        return true;
    }

    function verifyEnclaveKey(bytes memory _signature, Attestation memory _attestation) external returns (bool) {
        return _verifyEnclaveKey(_signature, _attestation);
    }

    //-------------------------------- Open methods end -------------------------------//

    //-------------------------------- Read only methods start -------------------------------//

    bytes32 private constant DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("marlin.oyster.AttestationVerifier"),
            keccak256("1")
        )
    );

    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes enclavePubKey,bytes32 imageId,uint256 timestampInMilliseconds)");

    function _verify(bytes memory _signature, Attestation memory _attestation) internal view {
        bytes32 _hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                keccak256(_attestation.enclavePubKey),
                _attestation.imageId,
                _attestation.timestampInMilliseconds
            )
        );
        bytes32 _digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _hashStruct));

        address _signer = ECDSA.recover(_digest, _signature);
        bytes32 _imageId = verifiedKeys[_signer];

        require(_imageId != bytes32(0), AttestationVerifierKeyNotVerified());
        require(whitelistedImages[_imageId], AttestationVerifierImageNotWhitelisted());
    }

    function verify(bytes memory _signature, Attestation memory _attestation) external view {
        return _verify(_signature, _attestation);
    }

    //-------------------------------- Read only methods end -------------------------------//
}
