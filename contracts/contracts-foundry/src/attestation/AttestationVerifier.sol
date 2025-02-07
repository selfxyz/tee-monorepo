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

    event AttestationVerifierUpdatedVerifier(
        IRiscZeroVerifier indexed verifier,
        IRiscZeroVerifier indexed old
    );
    event AttestationVerifierUpdatedGuestId(
        bytes32 indexed guestId,
        bytes32 indexed old
    );
    event AttestationVerifierUpdatedPcrs(bytes indexed pcrs, bytes indexed old);
    event AttestationVerifierUpdatedRootKey(
        bytes indexed rootKey,
        bytes indexed old
    );
    event AttestationVerifierUpdatedMaxAge(uint256 maxAge, uint256 old);
    event AttestationVerifierEnclaveImageWhitelisted(bytes32 indexed imageId);
    event AttestationVerifierEnclaveImageRevoked(bytes32 indexed imageId);
    event AttestationVerifierEnclaveKeyWhitelisted(
        address indexed enclaveAddress,
        bytes32 indexed imageId,
        address indexed enclavePubkey
    );
    event AttestationVerifierEnclaveKeyRevoked(address indexed enclaveAddress);
    event AttestationVerifierEnclaveKeyVerified(
        address indexed enclaveAddress,
        bytes32 indexed imageId,
        address indexed enclavePubkey
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
        EnclaveImage memory _enclaveImage
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);

        _updateVerifier(_verifier);
        _updateGuestId(_guestId);
        _updateRootKey(_rootKey);
        _updateMaxAge(_maxAge);

        _whitelistEnclaveImage(_enclaveImage);
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

    function _updateMaxAge(bytes memory _maxAge) internal {
        emit AttestationVerifierUpdatedMaxAge(_maxAge, maxAge);
        maxAge = _maxAge;
    }

    function _pubKeyToAddress(
        bytes memory _pubKey
    ) internal pure returns (address) {
        require(_pubKey.length == 64, AttestationVerifierPubkeyLengthInvalid());

        bytes32 _hash = keccak256(_pubKey);
        return address(uint160(uint256(_hash)));
    }

    function _whitelistEnclaveImage(
        EnclaveImage memory _image
    ) internal returns (bytes32, bool) {
        require(_image.PCR0.length == 48, AttestationVerifierPCRsInvalid());
        require(_image.PCR1.length == 48, AttestationVerifierPCRsInvalid());
        require(_image.PCR2.length == 48, AttestationVerifierPCRsInvalid());

        bytes32 _imageId = keccak256(
            abi.encodePacked(
                _image.PCR0,
                _image.PCR1,
                _image.PCR2,
                _image.userData
            )
        );
        if (!(whitelistedImages[_imageId].PCR0.length == 0))
            return (_imageId, false);

        whitelistedImages[_imageId] = EnclaveImage(
            _image.PCR0,
            _image.PCR1,
            _image.PCR2
        );
        emit AttestationVerifierEnclaveImageWhitelisted(
            _imageId,
            _image.PCR0,
            _image.PCR1,
            _image.PCR2,
            _image.userData
        );

        return (_imageId, true);
    }

    function _revokeEnclaveImage(bytes32 imageId) internal returns (bool) {
        if (!(whitelistedImages[imageId].PCR0.length != 0)) return false;

        delete whitelistedImages[imageId];
        emit EnclaveImageRevoked(imageId);

        return true;
    }

    function _whitelistEnclaveKey(
        bytes memory enclavePubKey,
        bytes32 imageId
    ) internal returns (bool) {
        if (!(whitelistedImages[imageId].PCR0.length != 0))
            revert AttestationVerifierImageNotWhitelisted();

        address enclaveAddress = _pubKeyToAddress(enclavePubKey);
        if (!(verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyWhitelisted(enclaveAddress, imageId, enclavePubKey);

        return true;
    }

    function _revokeEnclaveKey(address enclaveAddress) internal returns (bool) {
        if (!(verifiedKeys[enclaveAddress] != bytes32(0))) return false;

        delete verifiedKeys[enclaveAddress];
        emit EnclaveKeyRevoked(enclaveAddress);

        return true;
    }

    function whitelistEnclaveImage(
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32, bool) {
        return _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    function revokeEnclaveImage(
        bytes32 imageId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveImage(imageId);
    }

    function whitelistEnclaveKey(
        bytes memory enclavePubKey,
        bytes32 imageId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _whitelistEnclaveKey(enclavePubKey, imageId);
    }

    function revokeEnclaveKey(
        address enclaveAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) returns (bool) {
        return _revokeEnclaveKey(enclaveAddress);
    }

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    uint256 public constant MAX_AGE = 300;

    function _verifyEnclaveKey(
        bytes memory signature,
        Attestation memory attestation
    ) internal returns (bool) {
        if (
            !(attestation.timestampInMilliseconds / 1000 >
                block.timestamp - MAX_AGE)
        ) revert AttestationVerifierAttestationTooOld();
        bytes32 imageId = keccak256(
            abi.encodePacked(
                attestation.PCR0,
                attestation.PCR1,
                attestation.PCR2
            )
        );
        if (!(whitelistedImages[imageId].PCR0.length != 0))
            revert AttestationVerifierImageNotWhitelisted();

        _verify(signature, attestation);

        address enclaveAddress = pubKeyToAddress(attestation.enclavePubKey);
        if (!(verifiedKeys[enclaveAddress] == bytes32(0))) return false;

        verifiedKeys[enclaveAddress] = imageId;
        emit EnclaveKeyVerified(
            enclaveAddress,
            imageId,
            attestation.enclavePubKey
        );

        return true;
    }

    function verifyEnclaveKey(
        bytes memory signature,
        Attestation memory attestation
    ) external returns (bool) {
        return _verifyEnclaveKey(signature, attestation);
    }

    //-------------------------------- Open methods end -------------------------------//

    //-------------------------------- Read only methods start -------------------------------//

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.AttestationVerifier"),
                keccak256("1")
            )
        );

    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256(
            "Attestation(bytes enclavePubKey,bytes PCR0,bytes PCR1,bytes PCR2,uint256 timestampInMilliseconds)"
        );

    function _verify(
        bytes memory signature,
        Attestation memory attestation
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                keccak256(attestation.enclavePubKey),
                keccak256(attestation.PCR0),
                keccak256(attestation.PCR1),
                keccak256(attestation.PCR2),
                attestation.timestampInMilliseconds
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct)
        );

        address signer = ECDSA.recover(digest, signature);
        bytes32 imageId = verifiedKeys[signer];

        if (!(imageId != bytes32(0)))
            revert AttestationVerifierKeyNotVerified();
        if (!(whitelistedImages[imageId].PCR0.length != 0))
            revert AttestationVerifierImageNotWhitelisted();
    }

    function verify(
        bytes memory signature,
        Attestation memory attestation
    ) external view {
        _verify(signature, attestation);
    }

    //-------------------------------- Read only methods end -------------------------------//
}
