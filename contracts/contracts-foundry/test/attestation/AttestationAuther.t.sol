// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "../../lib/forge-std/src/Test.sol";
import {AttestationAuther} from "../../src/attestation/AttestationAuther.sol";
import {IAttestationVerifier} from "../../src/attestation/IAttestationVerifier.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract TestAttestationAuther is AttestationAuther, IAttestationVerifier {
    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
    ) AttestationAuther(
        _admin,
        _approver,
        _revoker,
        _attestationVerifier,
        address(this),
        _guestId,
        _rootKey,
        _maxAgeMs,
        _imageId,
        _family
    ) {}
}

contract AttestationAutherTestConstruction is Test {
    function test_Construction(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId,
        bytes32 _family
    ) public {
        MockAttestationVerifier mockVerifier = new MockAttestationVerifier();
        
        vm.expectEmit();
        emit AttestationAuther.RoleGranted(bytes32(0), _admin, address(this));
        
        vm.expectEmit();
        emit AttestationAuther.RoleGranted(keccak256("APPROVER_ROLE"), _approver, address(this));
        
        vm.expectEmit();
        emit AttestationAuther.RoleGranted(keccak256("REVOKER_ROLE"), _revoker, address(this));
        
        TestAttestationAuther auther = new TestAttestationAuther(
            _admin,
            _approver,
            _revoker,
            mockVerifier,
            _verifier,
            _guestId,
            _rootKey,
            _maxAgeMs,
            _imageId,
            _family
        );

        assertTrue(auther.hasRole(auther.DEFAULT_ADMIN_ROLE(), _admin));
        assertTrue(auther.hasRole(auther.APPROVER_ROLE(), _approver));
        assertTrue(auther.hasRole(auther.REVOKER_ROLE(), _revoker));
        assertEq(address(auther.attestationVerifier()), address(mockVerifier));
    }
}

contract AttestationAutherTestVerifyEnclave is Test {
    address admin;
    address approver;
    address revoker;
    IRiscZeroVerifier verifier;
    bytes32 guestId;
    bytes rootKey;
    uint256 maxAgeMs;
    bytes32 imageId;
    bytes32 family;
    TestAttestationAuther auther;
    MockAttestationVerifier mockVerifier;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        verifier = IRiscZeroVerifier(makeAddr("verifier"));
        guestId = bytes32(vm.randomUint());
        rootKey = vm.randomBytes(96);
        maxAgeMs = 2000;
        imageId = bytes32(vm.randomUint());
        family = bytes32(vm.randomUint());
        mockVerifier = new MockAttestationVerifier();
        
        auther = new TestAttestationAuther(
            admin,
            approver,
            revoker,
            mockVerifier,
            verifier,
            guestId,
            rootKey,
            maxAgeMs,
            imageId,
            family
        );
    }

    function test_VerifyEnclave_RiscZero(
        bytes calldata _seal,
        bytes calldata _pubkey,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        
        bytes32 _journalDigest = 
            sha256(abi.encodePacked(_timestampInMilliseconds, rootKey, uint8(64), _pubkey, imageId));
        
        vm.mockCallRevert(address(verifier), abi.encode(), abi.encode());
        bytes memory _calldata = 
            abi.encodeWithSelector(IRiscZeroVerifier.verify.selector, _seal, guestId, _journalDigest);
        vm.mockCall(address(verifier), _calldata, abi.encode());
        
        vm.expectCall(address(verifier), _calldata, 1);
        bytes32 _addr = bytes32(uint256(uint160(uint256(keccak256(_pubkey))));
        vm.expectEmit();
        emit AttestationAuther.VerifiedKeysVerified(_addr, imageId, _pubkey);
        vm.warp(4);

        auther.verifyEnclave(_seal, _pubkey, imageId, _timestampInMilliseconds);
    }

    function test_VerifyEnclave_Signature(
        bytes memory _signature,
        bytes memory _pubkey,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        
        IAttestationVerifier.Attestation memory attestation = IAttestationVerifier.Attestation({
            enclavePubKey: _pubkey,
            imageId: imageId,
            timestampInMilliseconds: _timestampInMilliseconds
        });

        vm.mockCall(address(mockVerifier), abi.encodeCall(mockVerifier.verify, (_signature, attestation)), abi.encode());
        vm.expectCall(address(mockVerifier), abi.encodeCall(mockVerifier.verify, (_signature, attestation)), 1);
        
        bytes32 _addr = bytes32(uint256(uint160(uint256(keccak256(_pubkey)))));
        vm.expectEmit();
        emit AttestationAuther.VerifiedKeysVerified(_addr, imageId, _pubkey);
        vm.warp(4);

        auther.verifyEnclave(_signature, attestation);
    }

    function test_VerifyEnclave_InvalidPubkeyLength(
        bytes calldata _seal,
        bytes calldata _pubkey,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length != 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 2001, type(uint64).max));
        
        vm.expectRevert(AttestationAuther.AttestationAutherPubkeyInvalid.selector);
        auther.verifyEnclave(_seal, _pubkey, imageId, _timestampInMilliseconds);
    }

    function test_VerifyEnclave_Expired(
        bytes calldata _seal,
        bytes calldata _pubkey,
        uint64 _timestampInMilliseconds
    ) public {
        vm.assume(_pubkey.length == 64);
        _timestampInMilliseconds = uint64(bound(_timestampInMilliseconds, 0, 2000));
        
        vm.expectRevert(AttestationAuther.AttestationAutherTooOld.selector);
        auther.verifyEnclave(_seal, _pubkey, imageId, _timestampInMilliseconds);
    }
}

contract AttestationAutherTestRoles is Test {
    address admin;
    address approver;
    address revoker;
    TestAttestationAuther auther;

    function setUp() public {
        admin = makeAddr("admin");
        approver = makeAddr("approver");
        revoker = makeAddr("revoker");
        auther = new TestAttestationAuther(
            admin,
            approver,
            revoker,
            new MockAttestationVerifier(),
            IRiscZeroVerifier(makeAddr("verifier")),
            bytes32(vm.randomUint()),
            vm.randomBytes(96),
            2000,
            bytes32(vm.randomUint()),
            bytes32(vm.randomUint())
        );
    }

    function test_UpdateVerifier_Role(address _nonAdmin) public {
        vm.assume(_nonAdmin != admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                auther.AccessControlUnauthorizedAccount.selector, _nonAdmin, auther.DEFAULT_ADMIN_ROLE()
            )
        );
        
        vm.prank(_nonAdmin);
        auther.updateVerifier(IRiscZeroVerifier(makeAddr("newVerifier")));
    }

    function test_ApproveImage_Role(address _nonApprover) public {
        vm.assume(_nonApprover != approver);
        vm.expectRevert(
            abi.encodeWithSelector(
                auther.AccessControlUnauthorizedAccount.selector, _nonApprover, auther.APPROVER_ROLE()
            )
        );
        
        vm.prank(_nonApprover);
        auther.approveImage(bytes32(vm.randomUint()), bytes32(vm.randomUint()));
    }

    function test_RevokeImage_Role(address _nonRevoker) public {
        vm.assume(_nonRevoker != revoker);
        vm.expectRevert(
            abi.encodeWithSelector(
                auther.AccessControlUnauthorizedAccount.selector, _nonRevoker, auther.REVOKER_ROLE()
            )
        );
        
        vm.prank(_nonRevoker);
        auther.revokeImage(bytes32(vm.randomUint()));
    }
}
