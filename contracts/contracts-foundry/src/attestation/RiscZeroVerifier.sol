// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

abstract contract RiscZeroVerifier {
    IRiscZeroVerifier public verifier;
    bytes32 public guestId;
    bytes public rootKey;
    uint256 public maxAge;

    event RiscZeroVerifierUpdatedVerifier(IRiscZeroVerifier indexed verifier, IRiscZeroVerifier indexed old);
    event RiscZeroVerifierUpdatedGuestId(bytes32 indexed guestId, bytes32 indexed old);
    event RiscZeroVerifierUpdatedPcrs(bytes indexed pcrs, bytes indexed old);
    event RiscZeroVerifierUpdatedRootKey(bytes indexed rootKey, bytes indexed old);
    event RiscZeroVerifierUpdatedMaxAge(uint256 maxAge, uint256 old);

    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAge
    ) {
        _updateVerifier(_verifier);
        _updateGuestId(_guestId);
        _updateRootKey(_rootKey);
        _updateMaxAge(_maxAge);
    }

    function _authorizeRiscZeroUpdate() internal virtual;

    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit RiscZeroVerifierUpdatedVerifier(_verifier, verifier);
        verifier = _verifier;
    }

    function _updateGuestId(bytes32 _guestId) internal {
        emit RiscZeroVerifierUpdatedGuestId(_guestId, guestId);
        guestId = _guestId;
    }

    function _updateRootKey(bytes memory _rootKey) internal {
        emit RiscZeroVerifierUpdatedRootKey(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    function _updateMaxAge(uint256 _maxAge) internal {
        emit RiscZeroVerifierUpdatedMaxAge(_maxAge, maxAge);
        maxAge = _maxAge;
    }

    function updateVerifier(IRiscZeroVerifier _verifier) external {
        _authorizeRiscZeroUpdate();
        return _updateVerifier(_verifier);
    }

    function updateGuestId(bytes32 _guestId) external {
        _authorizeRiscZeroUpdate();
        return _updateGuestId(_guestId);
    }

    function updateRootKey(bytes calldata _rootKey) external {
        _authorizeRiscZeroUpdate();
        return _updateRootKey(_rootKey);
    }

    function updateMaxAge(uint256 _maxAge) external {
        _authorizeRiscZeroUpdate();
        return _updateMaxAge(_maxAge);
    }
}
