// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {AccessControl} from "../../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

import {AttestationAuther} from "./AttestationAuther.sol";
import {IAttestationVerifier} from "./IAttestationVerifier.sol";

contract AttestationVerifier is AttestationAuther, IAttestationVerifier {
    constructor(
        address _admin,
        address _approver,
        address _revoker,
        IRiscZeroVerifier _verifier,
        bytes32 _guestId,
        bytes memory _rootKey,
        uint256 _maxAgeMs,
        bytes32 _imageId
    )
        AttestationAuther(
            _admin,
            _approver,
            _revoker,
            IAttestationVerifier(address(this)),
            _verifier,
            _guestId,
            _rootKey,
            _maxAgeMs,
            _imageId,
            DEFAULT_FAMILY
        )
    {}

    bytes32 public constant DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("marlin.oyster.AttestationVerifier"),
            keccak256("1")
        )
    );

    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes enclavePubKey,bytes32 imageId,uint256 timestampInMilliseconds)");

    function verify(bytes memory _signature, Attestation memory _attestation) external view {
        bytes32 _hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                keccak256(_attestation.enclavePubKey),
                _attestation.imageId,
                _attestation.timestampInMilliseconds
            )
        );
        bytes32 _digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, _hashStruct));

        address _signer = ECDSA.recover(_digest, _signature);
        _ensureKeyVerified(bytes32(uint256(uint160(_signer))));
    }
}
