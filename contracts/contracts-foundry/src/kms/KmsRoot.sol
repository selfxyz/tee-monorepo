// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IRiscZeroVerifier} from "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract KmsRoot is Ownable {
    uint256 public immutable MAX_AGE;

    IRiscZeroVerifier public verifier;
    bytes32 public imageId;
    bytes public pcrs;
    bytes public rootKey;

    mapping(address => bool) public isVerified;

    error KmsRootTooOld();
    error KmsRootLengthInvalid();

    event KmsRootUpdatedVerifier(
        IRiscZeroVerifier indexed verifier,
        IRiscZeroVerifier indexed old
    );
    event KmsRootUpdatedImageId(bytes32 indexed imageId, bytes32 indexed old);
    event KmsRootUpdatedPcrs(bytes indexed pcrs, bytes indexed old);
    event KmsRootUpdatedRootKey(bytes indexed rootKey, bytes indexed old);
    event KmsRootVerified(address indexed addr);

    constructor(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        bytes memory _rootKey,
        uint256 _maxAge
    ) Ownable(_owner) {
        MAX_AGE = _maxAge;

        _updateVerifier(_verifier);
        _updateImageId(_imageId);
        _updatePcrs(_pcrs);
        _updateRootKey(_rootKey);
    }

    function updateVerifier(IRiscZeroVerifier _verifier) external onlyOwner {
        _updateVerifier(_verifier);
    }

    function updateImageId(bytes32 _imageId) external onlyOwner {
        _updateImageId(_imageId);
    }

    function updatePcrs(bytes calldata _pcrs) external onlyOwner {
        _updatePcrs(_pcrs);
    }

    function updateRootKey(bytes calldata _rootKey) external onlyOwner {
        _updateRootKey(_rootKey);
    }

    function verify(
        bytes calldata _signerPubkey,
        bytes calldata _seal,
        uint64 _timestampInMilliseconds,
        bytes calldata _pcrs
    ) external {
        require(
            _timestampInMilliseconds > (block.timestamp - MAX_AGE) * 1000,
            KmsRootTooOld()
        );
        require(_signerPubkey.length < 256, KmsRootLengthInvalid());
        bytes32 _journalDigest = sha256(
            abi.encodePacked(
                _timestampInMilliseconds,
                _pcrs,
                rootKey,
                uint8(_signerPubkey.length),
                _signerPubkey,
                uint16(0)
            )
        );
        verifier.verify(_seal, imageId, _journalDigest);

        address _addr = _pubkeyToAddress(_signerPubkey);
        isVerified[_addr] = true;

        emit KmsRootVerified(_addr);
    }

    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit KmsRootUpdatedVerifier(_verifier, verifier);
        verifier = _verifier;
    }

    function _updateImageId(bytes32 _imageId) internal {
        emit KmsRootUpdatedImageId(_imageId, imageId);
        imageId = _imageId;
    }

    function _updatePcrs(bytes memory _pcrs) internal {
        emit KmsRootUpdatedPcrs(_pcrs, pcrs);
        pcrs = _pcrs;
    }

    function _updateRootKey(bytes memory _rootKey) internal {
        emit KmsRootUpdatedRootKey(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    function _pubkeyToAddress(
        bytes calldata _pubkey
    ) internal pure returns (address) {
        require(_pubkey.length == 64, KmsRootLengthInvalid());

        bytes32 _hash = keccak256(_pubkey);
        return address(uint160(uint256(_hash)));
    }
}
