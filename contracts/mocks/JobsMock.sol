// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract JobsMock {

    struct ExecutionEnv {
        // The fee paid to executors per millisecond.
        uint256 executionFeePerMs;
        // The staking reward per millisecond, paid to the payment pool.
        uint256 stakingRewardPerMs;
    }

    mapping(uint8 => ExecutionEnv) public executionEnv;

    error JobsMockError();


    constructor(
        uint8 _env,
        uint256 _executionFeePerMs,
        uint256 _stakingRewardPerMs
    ) {
        executionEnv[_env] = ExecutionEnv({
            executionFeePerMs: _executionFeePerMs,
            stakingRewardPerMs: _stakingRewardPerMs
        });
    }

    function createJob(
        uint8 _env,
        bytes32 _codehash,
        bytes memory _codeInputs,
        uint256 _deadline // in milliseconds
    ) external returns (uint256) {
        revert JobsMockError();
    }

    function getJobExecutionFeePerMs(uint8 _env) public view returns (uint256) {
        return executionEnv[_env].executionFeePerMs + executionEnv[_env].stakingRewardPerMs;
    }
}
