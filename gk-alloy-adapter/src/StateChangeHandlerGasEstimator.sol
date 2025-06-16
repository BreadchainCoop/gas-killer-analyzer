// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { StateChangeHandlerLib, StateUpdateType } from "../lib/gas-killer-avs-sol/src/StateChangeHandlerLib.sol";

contract StateChangeHandlerGasEstimator {
    function warmSlots(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 slot = slots[i];
            assembly {
                // 1 is dummy value
                sstore(slot, 1)
            }
        }
    }

    function coolSlots(bytes32[] calldata slots) external {
        for (uint256 i = 0; i < slots.length; i++) {
            bytes32 slot = slots[i];
            assembly {
                sstore(slot, 0)
            }
        }
    }

    function runStateUpdatesCall(StateUpdateType[] memory types, bytes[] memory args) external {
        StateChangeHandlerLib._runStateUpdates(types, args);
    }
}
