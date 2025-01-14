// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import "../../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

contract KmsRoot is Ownable {
    uint256 public immutable MAX_AGE;

    IRiscZeroVerifier public verifier;
    bytes32 public imageId;
    bytes public pcrs;
    bytes public rootKey;

    mapping(address => bool) public isVerified;

    error RootKmsTooOld();
    error RootKmsPubkeyLengthInvalid();

    event RootKmsVerifierUpdated(
        IRiscZeroVerifier indexed verifier,
        IRiscZeroVerifier indexed old
    );
    event RootKmsImageIdUpdated(bytes32 indexed imageId, bytes32 indexed old);
    event RootKmsPcrsUpdated(bytes indexed pcrs, bytes indexed old);
    event RootKmsRootKeyUpdated(bytes indexed rootKey, bytes indexed old);
    event RootKmsVerified(address indexed addr);

    constructor(
        address _owner,
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        bytes memory _pcrs,
        uint256 maxAge
    ) Ownable(_owner) {
        MAX_AGE = maxAge;

        _updateVerifier(_verifier);
        _updateImageId(_imageId);
        _updatePcrs(_pcrs);
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
            RootKmsTooOld()
        );
        require(_signerPubkey.length < 256, RootKmsPubkeyLengthInvalid());
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

        address addr = _pubkeyToAddress(_signerPubkey);
        isVerified[addr] = true;

        emit RootKmsVerified(addr);
    }

    function _updateVerifier(IRiscZeroVerifier _verifier) internal {
        emit RootKmsVerifierUpdated(_verifier, verifier);
        verifier = _verifier;
    }

    function _updateImageId(bytes32 _imageId) internal {
        emit RootKmsImageIdUpdated(_imageId, imageId);
        imageId = _imageId;
    }

    function _updatePcrs(bytes memory _pcrs) internal {
        emit RootKmsPcrsUpdated(_pcrs, pcrs);
        pcrs = _pcrs;
    }

    function _updateRootKey(bytes calldata _rootKey) internal {
        emit RootKmsRootKeyUpdated(_rootKey, rootKey);
        rootKey = _rootKey;
    }

    function _pubkeyToAddress(
        bytes calldata _pubkey
    ) internal pure returns (address) {
        require(_pubkey.length == 64, RootKmsPubkeyLengthInvalid());

        bytes32 hash = keccak256(_pubkey);
        return address(uint160(uint256(hash)));
    }
}
