// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {RiscZeroVerifier} from "../../src/attestation/RiscZeroVerifier.sol";

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract TestRiscZeroVerifier is RiscZeroVerifier {
    bool public authorized;

    error NotAuthorized();

    constructor(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAge, bool _authorized)
        RiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAge)
    {
        authorized = _authorized;
    }

    function setAuthorized(bool _authorized) external {
        authorized = _authorized;
    }

    function _authorizeRiscZeroUpdate() internal virtual override {
        require(authorized, NotAuthorized());
    }
}

contract RiscZeroVerifierTestConstruction is Test {
    function test_Construction(IRiscZeroVerifier _verifier, bytes32 _guestId, bytes memory _rootKey, uint256 _maxAge)
        public
    {
        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedVerifier(_verifier, IRiscZeroVerifier(address(0)));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedGuestId(_guestId, bytes32(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedRootKey(_rootKey, new bytes(0));

        vm.expectEmit();
        emit RiscZeroVerifier.RiscZeroVerifierUpdatedMaxAge(_maxAge, 0);

        TestRiscZeroVerifier _riscZeroVerifier = new TestRiscZeroVerifier(_verifier, _guestId, _rootKey, _maxAge, true);

        assertEq(address(_riscZeroVerifier.verifier()), address(_verifier));
        assertEq(_riscZeroVerifier.guestId(), _guestId);
        assertEq(_riscZeroVerifier.rootKey(), _rootKey);
        assertEq(_riscZeroVerifier.maxAge(), _maxAge);
    }
}
