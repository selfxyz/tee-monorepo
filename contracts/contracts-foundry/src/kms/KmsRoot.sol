// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {RiscZeroVerifier} from "../attestation/RiscZeroVerifier.sol";

/// @title KMS Root Contract
/// @notice Manages list of KMS servers allowed to decrypt root key
contract KmsRoot is Ownable, RiscZeroVerifier {
    /// @notice Enclave image ID
    bytes32 public imageId;
    /// @notice Mapping of addresses to their verification status
    mapping(address => bool) public isVerified;

    /// @notice Thrown when input length is invalid (public key must be 64 bytes)
    error KmsRootLengthInvalid();

    /// @notice Emitted when an address is verified
    /// @param addr The verified address
    event KmsRootVerified(address indexed addr);

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
    ) Ownable(_owner) RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAgeMs) {
        imageId = _imageId;
    }

    /// @notice Converts a public key to an Ethereum address
    /// @param _pubkey Public key to convert
    /// @return Ethereum address derived from the public key
    /// @dev Expects a 64-byte public key and returns the keccak256 hash as an address
    function _pubkeyToAddress(bytes calldata _pubkey) internal pure returns (address) {
        require(_pubkey.length == 64, KmsRootLengthInvalid());

        bytes32 _hash = keccak256(_pubkey);
        return address(uint160(uint256(_hash)));
    }

    /// @notice Authorizes the owner to execute parameter updates
    function _authorizeRiscZeroUpdate() internal virtual override onlyOwner {}

    /// @notice Verifies a KMS attestation
    /// @param _seal Proof seal from RiscZero
    /// @param _pubkey Attestation public key
    /// @param _imageId Enclave image ID
    /// @param _timestampInMilliseconds Attestation timestamp in milliseconds
    /// @dev Verifies the attestation and marks the derived address as verified if successful
    function verify(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampInMilliseconds)
        external
    {
        address _addr = _pubkeyToAddress(_pubkey);

        _verify(_seal, _pubkey, _imageId, _timestampInMilliseconds);

        isVerified[_addr] = true;

        emit KmsRootVerified(_addr);
    }
}
