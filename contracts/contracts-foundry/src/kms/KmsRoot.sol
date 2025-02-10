// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {RiscZeroVerifier, RiscZeroVerifierDefault} from "../attestation/RiscZeroVerifier.sol";
import {VerifiedKeys, VerifiedKeysDefault} from "../attestation/VerifiedKeys.sol";

/// @title KMS Root Contract
/// @notice Manages list of KMS servers allowed to decrypt root key
contract KmsRoot is Ownable, RiscZeroVerifierDefault, VerifiedKeysDefault {
    /// @notice Thrown when input length is invalid (public key must be 64 bytes)
    error KmsRootLengthInvalid();

    /// @notice Initializes the KmsRoot contract
    /// @param _owner Address of the contract owner
    /// @param _verifier Address of the RISC Zero verifier contract
    /// @param _imageId Image ID for verification
    /// @param _rootKey Initial root key
    /// @param _maxAgeMs Maximum age allowed for attestation timestamps
    constructor(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    )
        Ownable(_owner)
        RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs)
        VerifiedKeys(_imageId, DEFAULT_FAMILY)
    {}

    /// @notice Authorizes the owner to execute parameter updates
    function _rzvAuthorizeUpdate() internal virtual override onlyOwner {}

    function _vkAuthorizeApprove() internal virtual override onlyOwner {}
    function _vkAuthorizeRevoke() internal virtual override onlyOwner {}

    function _vkTransformPubkey(bytes memory _pubkey) internal virtual override returns (bytes32) {
        require(_pubkey.length == 64, KmsRootLengthInvalid());

        bytes32 _hash = keccak256(_pubkey);
        return bytes32(uint256(uint160(uint256(_hash))));
    }

    /// @notice Verifies a KMS attestation
    /// @param _seal Proof seal from RiscZero
    /// @param _pubkey Attestation public key
    /// @param _imageId Enclave image ID
    /// @param _timestampInMilliseconds Attestation timestamp in milliseconds
    /// @dev Verifies the attestation and marks the derived address as verified if successful
    function verify(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampInMilliseconds)
        external
    {
        _verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);
        _setKeyVerified(_pubkey, _imageId);
    }
}
