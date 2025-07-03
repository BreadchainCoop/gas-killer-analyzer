// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {DelegateCallTestMain} from "../src/DelegateCallTestContracts.sol";

contract DeployAndRunDelegateCallTest is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        DelegateCallTestMain main = new DelegateCallTestMain();
        main.run();
        vm.stopBroadcast();
    }
} 