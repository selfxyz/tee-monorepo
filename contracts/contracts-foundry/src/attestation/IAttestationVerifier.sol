// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Interface for verifying attestations through enclave signatures
interface IAttestationVerifier {
    /// @notice Attestation data structure containing enclave information
    /// @param enclavePubKey Public key of the enclave
    /// @param imageId Image id of the enclave
    /// @param timestampMs Attestation timestamp in milliseconds
    struct Attestation {
        bytes32 imageId;
        uint256 timestampMs;
        bytes publicKey;
        bytes userData;
    }

    /// @notice Verifies the signature against the attestation
    /// @dev Should revert if signature verification fails
    /// @param signature ECDSA signature of the attestation data
    /// @param attestation Attestation data structure to verify
    function verify(bytes memory signature, Attestation memory attestation) external view;
}
