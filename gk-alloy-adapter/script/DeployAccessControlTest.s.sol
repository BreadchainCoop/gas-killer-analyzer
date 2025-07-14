// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {AccessControlTestMain, AccessControlA} from "../src/AccessControlTestContracts.sol";

contract DeployAccessControlTest is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        AccessControlTestMain main = new AccessControlTestMain();
        console.log("AccessControlTestMain address", address(main));
        vm.stopBroadcast();
    }
} 