// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {IAttestationVerifier} from "./IAttestationVerifier.sol";
import {RiscZeroVerifier, RiscZeroVerifierDefault} from "./RiscZeroVerifier.sol";
import {VerifiedKeys, VerifiedKeysDefault} from "./VerifiedKeys.sol";

contract AttestationAuther is AccessControl, RiscZeroVerifierDefault, VerifiedKeysDefault {
    bytes32 public constant APPROVER_ROLE = keccak256("APPROVER_ROLE");
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    IAttestationVerifier public attestationVerifier;

    error AttestationAutherTooOld();
    error AttestationAutherPubkeyInvalid();

    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IAttestationVerifier _attestationVerifier,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
    ) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) VerifiedKeys(_imageId, _family) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(APPROVER_ROLE, _approver);
        _grantRole(REVOKER_ROLE, _revoker);
        attestationVerifier = _attestationVerifier;
    }

    function _rzvAuthorizeUpdate() internal virtual override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function _vkAuthorizeApprove() internal virtual override onlyRole(APPROVER_ROLE) {}

    function _vkAuthorizeRevoke() internal virtual override onlyRole(REVOKER_ROLE) {}

    function _vkTransformPubkey(bytes memory _pubkey) internal virtual override returns (bytes32) {
        require(_pubkey.length == 64, AttestationAutherPubkeyInvalid());

        bytes32 _hash = keccak256(_pubkey);
        return bytes32(uint256(uint160(uint256(_hash))));
    }

    function verifyEnclave(
        bytes calldata _seal,
        bytes calldata _pubkey,
        bytes32 _imageId,
        uint64 _timestampInMilliseconds
    ) external {
        _verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
        _setKeyVerified(_pubkey, _imageId);
    }

    function verifyEnclave(bytes memory _signature, IAttestationVerifier.Attestation memory _attestation) external {
        require(_attestation.timestampInMilliseconds > block.timestamp * 1000 - maxAgeMs, AttestationAutherTooOld());
        attestationVerifier.verify(_signature, _attestation);
        _setKeyVerified(_attestation.enclavePubKey, _attestation.imageId);
    }
}
