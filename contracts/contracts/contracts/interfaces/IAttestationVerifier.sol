// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IAttestationVerifier {
    struct Attestation {
        bytes enclavePubKey;
        bytes32 imageId;
        uint256 timestampInMilliseconds;
    }
    function verify(bytes memory signature, Attestation memory attestation) external view;
}
