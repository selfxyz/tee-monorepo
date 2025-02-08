// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

abstract contract AttestationAuther {
    IAttestationVerifier public verifier;
    // image id -> approved or not
    mapping(bytes32 => bool) public isApproved;
    // enclave key, transformed -> image id
    mapping(bytes32 => bytes32) public isVerified;
    uint256 public maxAgeMs;

    error AttestationAutherTooOld();
    error AttestationAutherNotApproved();

    event AttestationAutherApproved(bytes32 indexed imageId);
    event AttestationAutherRevoked(bytes32 indexed imageId);
    event AttestationAutherVerified(bytes32 indexed enclaveKey, bytes32 indexed imageId, bytes indexed enclavePubkey);

    constructor(IAttestationVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        _approve(_imageId);
    }

    function _transformAutherPubkey(bytes memory _pubkey) internal virtual returns (bytes32);

    function _approve(bytes32 _imageId) internal returns (bool) {
        if (isApproved[_imageId]) return false;

        isApproved[_imageId] = true;
        emit AttestationAutherApproved(_imageId);

        return true;
    }

    function _revoke(bytes32 _imageId) internal returns (bool) {
        if (!isApproved[_imageId]) return false;

        delete isApproved[_imageId];
        emit AttestationAutherRevoked(_imageId);

        return true;
    }

    function _verifyEnclave(bytes memory _signature, IAttestationVerifier.Attestation memory _attestation) internal returns (bool) {
        require(_attestation.timestampInMilliseconds > block.timestamp * 1000 - maxAgeMs, AttestationAutherTooOld());
        bytes32 _imageId = _attestation.imageId;
        require(isApproved[_imageId], AttestationAutherNotApproved());

        verifier.verify(_signature, _attestation);

        bytes32 _enclaveKey = _transformAutherPubkey(_attestation.enclavePubKey);
        if (isVerified[_enclaveKey] != bytes32(0)) return false;

        isVerified[_enclaveKey] = _imageId;
        emit AttestationAutherVerified(_enclaveKey, _imageId, _attestation.enclavePubKey);

        return true;
    }
}
