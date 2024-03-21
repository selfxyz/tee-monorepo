// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";

contract LockUpgradeable is
    Initializable // initializer
{
    struct Lock {
        uint256 unlockTime;
        uint256 iValue;
    }

    /// @custom:storage-location erc7201:marlin.oyster.storage.Lock
    struct LockStorage {
        mapping(bytes32 => Lock) locks;
        mapping(bytes32 => uint256) lockWaitTimes;
    }

    // keccak256(abi.encode(uint256(keccak256("marlin.oyster.storage.Lock")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant LockStorageLocation = 0x2ba99b043df9e6db72821769dcc0757c8c1b1dc979dd0c3217f2e035fed90700;

    function _getLockStorage() private pure returns (LockStorage storage $) {
        assembly {
            $.slot := LockStorageLocation
        }
    }

    enum LockStatus {
        None,
        Unlocked,
        Locked
    }

    error LockLengthMismatch();

    event LockWaitTimeUpdated(bytes32 indexed selector, uint256 prevLockTime, uint256 updatedLockTime);
    event LockCreated(bytes32 indexed selector, bytes32 indexed key, uint256 iValue, uint256 unlockTime);
    event LockDeleted(bytes32 indexed selector, bytes32 indexed key, uint256 iValue);

    function __Lock_init_unchained(
        bytes32[] memory _selectors,
        uint256[] memory _lockWaitTimes
    ) internal onlyInitializing {
        _updateLockWaitTimes(_selectors, _lockWaitTimes);
    }

    function _lockWaitTime(bytes32 _lockId) internal view returns (uint256) {
        LockStorage storage $ = _getLockStorage();

        return $.lockWaitTimes[_lockId];
    }

    function lockWaitTime(bytes32 _lockId) public view returns (uint256) {
        return _lockWaitTime(_lockId);
    }

    function _lockStatus(bytes32 _selector, bytes32 _key) internal view returns (LockStatus) {
        LockStorage storage $ = _getLockStorage();

        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _unlockTime = $.locks[_lockId].unlockTime;
        if (_unlockTime == 0) {
            return LockStatus.None;
        } else if (_unlockTime <= block.timestamp) {
            return LockStatus.Unlocked;
        } else {
            return LockStatus.Locked;
        }
    }

    function _lock(bytes32 _selector, bytes32 _key, uint256 _iValue) internal returns (uint256) {
        LockStorage storage $ = _getLockStorage();

        require(_lockStatus(_selector, _key) == LockStatus.None);

        uint256 _duration = $.lockWaitTimes[_selector];
        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _unlockTime = block.timestamp + _duration;
        $.locks[_lockId].unlockTime = _unlockTime;
        $.locks[_lockId].iValue = _iValue;

        emit LockCreated(_selector, _key, _iValue, _unlockTime);

        return _unlockTime;
    }

    function _revertLock(bytes32 _selector, bytes32 _key) internal returns (uint256) {
        LockStorage storage $ = _getLockStorage();

        bytes32 _lockId = keccak256(abi.encodePacked(_selector, _key));
        uint256 _iValue = $.locks[_lockId].iValue;
        delete $.locks[_lockId];

        emit LockDeleted(_selector, _key, _iValue);

        return _iValue;
    }

    function _unlock(bytes32 _selector, bytes32 _key) internal returns (uint256) {
        require(_lockStatus(_selector, _key) == LockStatus.Unlocked);
        return _revertLock(_selector, _key);
    }

    function _cloneLock(bytes32 _selector, bytes32 _fromKey, bytes32 _toKey) internal {
        LockStorage storage $ = _getLockStorage();

        bytes32 _fromLockId = keccak256(abi.encodePacked(_selector, _fromKey));
        bytes32 _toLockId = keccak256(abi.encodePacked(_selector, _toKey));

        uint256 _unlockTime = $.locks[_fromLockId].unlockTime;
        uint256 _iValue = $.locks[_fromLockId].iValue;

        $.locks[_toLockId].unlockTime = _unlockTime;
        $.locks[_toLockId].iValue = _iValue;

        emit LockCreated(_selector, _toKey, _iValue, _unlockTime);
    }

    function _updateLockWaitTime(bytes32 _selector, uint256 _newLockWaitTime) internal {
        LockStorage storage $ = _getLockStorage();

        emit LockWaitTimeUpdated(_selector, $.lockWaitTimes[_selector], _newLockWaitTime);
        $.lockWaitTimes[_selector] = _newLockWaitTime;
    }

    function _updateLockWaitTimes(bytes32[] memory _selectors, uint256[] memory _newLockWaitTimes) internal {
        if (!(_selectors.length == _newLockWaitTimes.length)) revert LockLengthMismatch();

        for (uint256 _i = 0; _i < _selectors.length; _i++) {
            _updateLockWaitTime(_selectors[_i], _newLockWaitTimes[_i]);
        }
    }
}
