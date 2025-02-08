// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

abstract contract AttestationAuther {
    IAttestationVerifier public verifier;
    // image id -> family
    mapping(bytes32 => bytes32) public images;
    // enclave key, transformed -> image id
    mapping(bytes32 => bytes32) public keys;
    uint256 public maxAgeMs;

    bytes32 public constant DEFAULT_FAMILY = keccak256("DEFAULT_FAMILY");

    error AttestationAutherTooOld();
    error AttestationAutherFamilyMismatch();

    event AttestationAutherApproved(bytes32 indexed imageId, bytes32 indexed family);
    event AttestationAutherRevoked(bytes32 indexed imageId, bytes32 indexed family);
    event AttestationAutherVerified(bytes32 indexed enclaveKey, bytes32 indexed imageId, bytes indexed enclavePubkey);

    constructor(IAttestationVerifier _verifier, bytes32 _imageId, bytes32 _family) {
        verifier = _verifier;
        _approve(_imageId, _family);
    }

    function _authorizeAutherApprove() internal virtual;
    function _authorizeAutherRevoke() internal virtual;
    function _transformAutherPubkey(bytes memory _pubkey) internal virtual returns (bytes32);

    function _approve(bytes32 _imageId, bytes32 _family) internal returns (bool) {
        if (images[_imageId] != bytes32(0)) {
            require(images[_imageId] == _family, AttestationAutherFamilyMismatch());

            return false;
        }

        images[_imageId] = _family;
        emit AttestationAutherApproved(_imageId, _family);

        return true;
    }

    function _revoke(bytes32 _imageId) internal returns (bool) {
        if (images[_imageId] == bytes32(0)) return false;

        emit AttestationAutherRevoked(_imageId, images[_imageId]);
        delete images[_imageId];

        return true;
    }

    function approve(bytes32 _imageId, bytes32 _family) external returns (bool) {
        _authorizeAutherApprove();
        return _approve(_imageId, _family);
    }

    function revoke(bytes32 _imageId) external returns (bool) {
        _authorizeAutherRevoke();
        return _revoke(_imageId);
    }

    function verifyEnclave(
        bytes memory _signature,
        IAttestationVerifier.Attestation memory _attestation,
        bytes32 _family
    ) external returns (bool) {
        require(_attestation.timestampInMilliseconds > block.timestamp * 1000 - maxAgeMs, AttestationAutherTooOld());

        bytes32 _imageId = _attestation.imageId;
        require(images[_imageId] == _family, AttestationAutherFamilyMismatch());

        verifier.verify(_signature, _attestation);

        bytes32 _enclaveKey = _transformAutherPubkey(_attestation.enclavePubKey);
        if (keys[_enclaveKey] != bytes32(0)) return false;

        keys[_enclaveKey] = _imageId;
        emit AttestationAutherVerified(_enclaveKey, _imageId, _attestation.enclavePubKey);

        return true;
    }
}
