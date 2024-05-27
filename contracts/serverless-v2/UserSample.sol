// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract UserSample {
    using SafeERC20 for IERC20;

    address public relayAddress;

    /// @notice refers to USDC token
    IERC20 public token;

    constructor(address _relayAddress, address _token) {
        relayAddress = _relayAddress;
        token = IERC20(_token);
    }

    event CalledBack(
        uint256 indexed jobId, 
        bytes32 codehash,
        bytes codeInputs,
        bytes outputs, 
        uint8 errorCode
    );

    // bytes32 txhash = 0xc7d9122f583971d4801747ab24cf3e83984274b8d565349ed53a73e0a547d113;

    function relayJob(
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _userTimeout,
        uint256 _maxGasPrice,
        uint256 _usdcDeposit,
        address _refundAccount,
        address _callbackContract
    ) external payable returns (bool success) {
        // usdcDeposit = _userTimeout * EXECUTION_FEE_PER_MS + GATEWAY_FEE_PER_JOB;
        token.safeIncreaseAllowance(relayAddress, _usdcDeposit);

        (bool _success, ) = relayAddress.call{value: msg.value}(
            abi.encodeWithSignature(
                "relayJob(bytes32,bytes,uint256,uint256,address,address)",
                _codehash,
                _codeInputs,
                _userTimeout,
                _maxGasPrice,
                _refundAccount,
                _callbackContract
            )
        );
        return _success;
    }

    function oysterResultCall(
        uint256 _jobId, 
        bytes32 _codehash,
        bytes calldata _codeInputs,
        bytes calldata _output, 
        uint8 _errorCode
    ) public {
        emit CalledBack(_jobId, _codehash, _codeInputs, _output, _errorCode);
    }

    receive() external payable {}
}
