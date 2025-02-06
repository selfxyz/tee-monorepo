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

    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER");

    IRiscZeroVerifier public verifier;
    bytes32 public imageId;
    bytes public rootKey;
    uint256 public maxAge;

    struct EnclaveImage {
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
        bytes userData;
    }

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

    event EnclaveImageWhitelisted(
        bytes32 indexed imageId,
        bytes PCR0,
        bytes PCR1,
        bytes PCR2
    );
    event EnclaveImageRevoked(bytes32 indexed imageId);
    event EnclaveKeyWhitelisted(
        address indexed enclaveAddress,
        bytes32 indexed imageId,
        bytes enclavePubKey
    );
    event EnclaveKeyRevoked(address indexed enclaveAddress);
    event EnclaveKeyVerified(
        address indexed enclaveAddress,
        bytes32 indexed imageId,
        bytes enclavePubKey
    );

    //-------------------------------- Events end --------------------------------//

    //-------------------------------- Constructor start --------------------------------//

    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _rootKey,
        uint256 _maxAge,
        EnclaveImage memory _enclaveImage
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);

        // TODO: set risczero params

        _whitelistEnclaveImage(_enclaveImage);
    }

    //-------------------------------- Constructor end --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    function _pubKeyToAddress(
        bytes memory pubKey
    ) internal pure returns (address) {
        if (!(pubKey.length == 64))
            revert AttestationVerifierPubkeyLengthInvalid();

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }

    function _whitelistEnclaveImage(
        EnclaveImage memory image
    ) internal returns (bytes32, bool) {
        if (
            !(image.PCR0.length == 48 &&
                image.PCR1.length == 48 &&
                image.PCR2.length == 48)
        ) revert AttestationVerifierPCRsInvalid();

        bytes32 imageId = keccak256(
            abi.encodePacked(image.PCR0, image.PCR1, image.PCR2)
        );
        if (!(whitelistedImages[imageId].PCR0.length == 0))
            return (imageId, false);

        whitelistedImages[imageId] = EnclaveImage(
            image.PCR0,
            image.PCR1,
            image.PCR2
        );
        emit EnclaveImageWhitelisted(
            imageId,
            image.PCR0,
            image.PCR1,
            image.PCR2
        );

        return (imageId, true);
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
