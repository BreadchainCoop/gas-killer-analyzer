// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { StateChangeHandlerLib, StateUpdateType } from "../lib/gas-killer-avs-sol/src/StateChangeHandlerLib.sol";

contract StateChangeHandlerGasEstimator {
    // IMPORTANT: do not make this state variable. Will mess up state
    address public immutable fallbackImpl;

    constructor(bytes memory deployedFallbackCode) {
        uint256 deployedFallbackCodeSize = deployedFallbackCode.length;
        require(deployedFallbackCodeSize > 0, DeployedFallbackCodeEmpty());
        require(deployedFallbackCodeSize < 2 ** 16, DeployedFallbackCodeTooLarge(deployedFallbackCodeSize));
        
        bytes2 deployedFallbackCodeSizeBytes2 = bytes2(uint16(deployedFallbackCodeSize));
        // dynamic initcode that deploys the fallback code
        bytes memory initCode = abi.encodePacked(
            bytes1(0x61), // PUSH2 (0)
            deployedFallbackCodeSizeBytes2, // (1)
            bytes1(0x60), // PUSH1 (3)
            bytes1(0x0c), // Offset in initcode to deployedFallbackCode (4)
            bytes1(0x5f), // PUSH0 (5)
            bytes1(0x39), // CODECOPY (DEST_OFFSET, SRC_OFFSET, LENGTH) (6)
            bytes1(0x61), // PUSH2 (7)
            deployedFallbackCodeSizeBytes2, // (8)
            bytes1(0x5f), // PUSH0 (10)
            bytes1(0xf3), // RETURN (OFFSET, LENGTH) (11)
            deployedFallbackCode
        );

        address impl;
        string memory errMsg = "CREATE call failed";
        uint256 errMsgLength = bytes(errMsg).length;
        assembly {
            impl := create(0, add(initCode, 0x20), mload(initCode))
            if iszero(impl) {
                revert(add(errMsg, 0x20), errMsgLength)
            }
        }
        fallbackImpl = impl;
    }

    function runStateUpdatesCall(StateUpdateType[] memory types, bytes[] memory args) external {
        StateChangeHandlerLib._runStateUpdates(types, args);
    }
}
