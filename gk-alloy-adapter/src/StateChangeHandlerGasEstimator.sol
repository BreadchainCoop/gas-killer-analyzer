// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { StateChangeHandlerLib, StateUpdateType } from "../lib/gas-killer-avs-sol/src/StateChangeHandlerLib.sol";

contract StateChangeHandlerGasEstimator {
    function runStateUpdatesCall(StateUpdateType[] memory types, bytes[] memory args) external {
        StateChangeHandlerLib._runStateUpdates(types, args);
    }
}
