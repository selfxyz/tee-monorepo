// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

abstract contract VerifiedKeys {
    function _vkGetImageFamily(bytes32 _imageId) internal view virtual returns (bytes32);
    function _vkSetImageFamily(bytes32 _imageId, bytes32 _family) internal virtual;

    function _vkGetEnclaveImage(bytes32 _key) internal view virtual returns (bytes32);
    function _vkSetEnclaveImage(bytes32 _key, bytes32 _imageId) internal virtual;

    function _vkAuthorizeApprove() internal virtual;
    function _vkAuthorizeRevoke() internal virtual;

    function _vkTransformPubkey(bytes memory _pubkey) internal virtual returns (bytes32);

    bytes32 public constant DEFAULT_FAMILY = keccak256("DEFAULT_FAMILY");

    error VerifiedKeysFamilyMismatch();
    error VerifiedKeysNotVerified();

    event VerifiedKeysApproved(bytes32 indexed imageId, bytes32 indexed family);
    event VerifiedKeysRevoked(bytes32 indexed imageId, bytes32 indexed family);
    event VerifiedKeysVerified(bytes32 indexed key, bytes32 indexed imageId, bytes indexed pubkey);

    constructor(bytes32 _imageId, bytes32 _family) {
        _approveImage(_imageId, _family);
    }

    function _approveImage(bytes32 _imageId, bytes32 _family) internal returns (bool) {
        bytes32 _currentFamily = _vkGetImageFamily(_imageId);
        if (_currentFamily != bytes32(0)) {
            require(_currentFamily == _family, VerifiedKeysFamilyMismatch());

            return false;
        }

        _vkSetImageFamily(_imageId, _family);
        emit VerifiedKeysApproved(_imageId, _family);

        return true;
    }

    function _revokeImage(bytes32 _imageId) internal returns (bool) {
        bytes32 _currentFamily = _vkGetImageFamily(_imageId);
        if (_currentFamily == bytes32(0)) return false;

        _vkSetImageFamily(_imageId, bytes32(0));
        emit VerifiedKeysRevoked(_imageId, _currentFamily);

        return true;
    }

    function approveImage(bytes32 _imageId, bytes32 _family) external returns (bool) {
        _vkAuthorizeApprove();
        return _approveImage(_imageId, _family);
    }

    function revokeImage(bytes32 _imageId) external returns (bool) {
        _vkAuthorizeRevoke();
        return _revokeImage(_imageId);
    }

    function _setKeyVerified(bytes memory _enclavePubkey, bytes32 _imageId) internal returns (bool) {
        bytes32 _key = _vkTransformPubkey(_enclavePubkey);
        if (_vkGetEnclaveImage(_key) != bytes32(0)) return false;

        _vkSetEnclaveImage(_key, _imageId);
        emit VerifiedKeysVerified(_key, _imageId, _enclavePubkey);

        return true;
    }

    function _ensureKeyVerified(bytes32 _key) internal view {
        bytes32 _imageId = _vkGetEnclaveImage(_key);
        require(_imageId != bytes32(0), VerifiedKeysNotVerified());
        // to check revocations
        require(_vkGetImageFamily(_imageId) != bytes32(0), VerifiedKeysNotVerified());
    }
}

abstract contract VerifiedKeysDefault is VerifiedKeys {
    // image id -> family
    mapping(bytes32 => bytes32) public images;
    // enclave key, transformed -> image id
    mapping(bytes32 => bytes32) public keys;

    function _vkGetImageFamily(bytes32 _imageId) internal view virtual returns (bytes32) {
        return images[_imageId];
    }
    
    function _vkSetImageFamily(bytes32 _imageId, bytes32 _family) internal virtual {
        images[_imageId] = _family;
    }

    function _vkGetEnclaveImage(bytes32 _key) internal view virtual returns (bytes32) {
        return keys[_key];
    }
    
    function _vkSetEnclaveImage(bytes32 _key, bytes32 _imageId) internal virtual {
        keys[_key] = _imageId;
    }
}
