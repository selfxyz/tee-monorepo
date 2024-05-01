// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

contract UserSample {
    address payable serverless_addr;

    constructor(address addr) {
        serverless_addr = payable(addr);
    }

    event CalledBack(uint256 indexed jobId, bytes outputs, uint8 errorCode);

    // bytes32 txhash = 0xc7d9122f583971d4801747ab24cf3e83984274b8d565349ed53a73e0a547d113;

    function relayJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _usdcDeposit,
        uint256 _callbackDeposit
    ) external payable returns (bool success) {
        // uint256 job_deposit = 1000000000;
        // uint256 callback_deposit = 1 ether;
        (bool _success,) = serverless_addr.call{value: _callbackDeposit}(
            abi.encodeWithSignature("relayJob(bytes32,bytes,uint256,uint256,uint256,uint256)",
                _codehash,
                _codeInputs,
                _userTimeout,
                _maxGasPrice,
                _usdcDeposit,
                _callbackDeposit
            )
        );
        return _success;
    }

    function oysterResultCall(uint256 jobId, bytes calldata output, uint8 errorCode) public {
        emit CalledBack(jobId, output, errorCode);
    }

    receive() external payable {}
}