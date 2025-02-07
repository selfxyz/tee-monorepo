// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

/// @title RiscZero based attestation verifier
/// @notice Contract for verifying RiscZero proofs of attestation verification
abstract contract RiscZeroVerifier {
    /// @notice Underlying RiscZero verifier contract
    IRiscZeroVerifier public verifier;
    /// @notice Expected guest image ID
    bytes32 public guestId;
    /// @notice Expected root public key of the attestation
    bytes public rootKey;
    /// @notice Maximum allowed age of attestations in milliseconds
    uint256 public maxAgeMs;

    /// @notice Thrown when attestation is too old
    error RiscZeroVerifierTooOld();
    /// @notice Thrown when public key exceeds maximum length of 256 bytes
    error RiscZeroVerifierPubkeyTooLong();

    /// @notice Emitted when verifier contract is updated
    /// @param verifier New verifier contract address
    /// @param old Previous verifier contract address
    event RiscZeroVerifierUpdatedVerifier(IRiscZeroVerifier indexed verifier, IRiscZeroVerifier indexed old);
    /// @notice Emitted when guest ID is updated
    /// @param guestId New guest ID
    /// @param old Previous guest ID
    event RiscZeroVerifierUpdatedGuestId(bytes32 indexed guestId, bytes32 indexed old);
    /// @notice Emitted when root key is updated
    /// @param rootKey New root key
    /// @param old Previous root key
    event RiscZeroVerifierUpdatedRootKey(bytes indexed rootKey, bytes indexed old);
    /// @notice Emitted when max age is updated
    /// @param maxAgeMs New maximum age
    /// @param old Previous maximum age
    event RiscZeroVerifierUpdatedMaxAge(uint256 maxAgeMs, uint256 old);

    /// @notice Initializes verification parameters
    /// @param _verifier Address of RiscZero verifier contract
    /// @param _guestId Expected guest image ID
    /// @param _rootKey Expected root public key
    /// @param _maxAgeMs Maximum allowed age in milliseconds
    constructor(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAgeMs) {
        _updateVerifier(_verifier);
        _updateGuestId(_guestId);
        _updateRootKey(_rootKey);
        _updateMaxAge(_maxAgeMs);
    }

    /// @notice Hook for authorization logic for parameter updates
    /// @dev Must be implemented by derived contracts to enforce access control
    function _authorizeRiscZeroUpdate() internal virtual;

    /// @dev Internal setter for verifier contract
    /// @param _verifier New verifier contract address
    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit RiscZeroVerifierUpdatedVerifier(_verifier, verifier);
        verifier = _verifier;
    }

    /// @dev Internal setter for guest ID
    /// @param _guestId New guest ID
    function _updateGuestId(bytes32 _guestId) internal {
        emit RiscZeroVerifierUpdatedGuestId(_guestId, guestId);
        guestId = _guestId;
    }

    /// @dev Internal setter for root key
    /// @param _rootKey New root key
    function _updateRootKey(bytes memory _rootKey) internal {
        emit RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    /// @dev Internal setter for maximum age
    /// @param _maxAgeMs New maximum age in milliseconds
    function _updateMaxAge(uint256 _maxAgeMs) internal {
        emit RiscZeroVerifierUpdatedMaxAge(_maxAgeMs, maxAgeMs);
        maxAgeMs = _maxAgeMs;
    }

    /// @notice Updates verifier contract address
    /// @dev Callable only by authorized accounts
    /// @param _verifier New verifier contract address
    function updateVerifier(IRiscZeroVerifier _verifier) external {
        _authorizeRiscZeroUpdate();
        return _updateVerifier(_verifier);
    }

    /// @notice Updates guest ID
    /// @dev Callable only by authorized accounts
    /// @param _guestId New guest ID
    function updateGuestId(bytes32 _guestId) external {
        _authorizeRiscZeroUpdate();
        return _updateGuestId(_guestId);
    }

    /// @notice Updates root key
    /// @dev Callable only by authorized accounts
    /// @param _rootKey New root key
    function updateRootKey(bytes calldata _rootKey) external {
        _authorizeRiscZeroUpdate();
        return _updateRootKey(_rootKey);
    }

    /// @notice Updates maximum age
    /// @dev Callable only by authorized accounts
    /// @param _maxAgeMs New maximum age in milliseconds
    function updateMaxAge(uint256 _maxAgeMs) external {
        _authorizeRiscZeroUpdate();
        return _updateMaxAge(_maxAgeMs);
    }

    /// @notice Verifies a RiscZero proof of attestation verification
    /// @dev Reverts if attestation is expired, pubkey too long, or verification fails
    /// @param _seal Proof seal from RiscZero
    /// @param _pubkey Attestation public key
    /// @param _imageId Enclave image ID
    /// @param _timestampInMilliseconds Attestation timestamp in milliseconds
    function verify(bytes calldata _seal, bytes calldata _pubkey, bytes32 _imageId, uint64 _timestampInMilliseconds)
        external
        view
    {
        require(_timestampInMilliseconds > block.timestamp * 1000 - maxAgeMs, RiscZeroVerifierTooOld());
        require(_pubkey.length <= 256, RiscZeroVerifierPubkeyTooLong());
        bytes32 _journalDigest =
            sha256(abi.encodePacked(_timestampInMilliseconds, rootKey, uint8(_pubkey.length), _pubkey, _imageId));
        verifier.verify(_seal, guestId, _journalDigest);
    }
}
