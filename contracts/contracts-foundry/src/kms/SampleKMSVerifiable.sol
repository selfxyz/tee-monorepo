// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";

import {IKMSVerifiable} from "./IKMSVerifiable.sol";

/// @title Sample KMS Verifiable Contract
/// @notice Manages list of image IDs allowed to derive keys
contract SampleKMSVerifiable is Ownable, IKMSVerifiable {
    /// @notice Mapping of verified image IDs
    mapping (bytes32 => bool) public images;

    constructor(
        bytes32[] memory _imageIds
    ) Ownable(msg.sender) {
        _whitelistImages(_imageIds);
    }

    function _whitelistImages(bytes32[] memory _imageIds) internal {
        for (uint i = 0; i < _imageIds.length; i++) {
            images[_imageIds[i]] = true;
        }
    }

    function whitelistImages(bytes32[] calldata _imageIds) onlyOwner external {
        _whitelistImages(_imageIds);
    }

    function blacklistImages(bytes32[] calldata _imageIds) onlyOwner external {
        for (uint i = 0; i < _imageIds.length; i++) {
            delete images[_imageIds[i]]  ;
        }
    }

    function oysterKMSVerify(bytes32 _imageId) external view override returns (bool) {
        return images[_imageId];
    }
}
