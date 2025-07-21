// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";

struct DebugData {
    uint256 preceedingBlocknumber;
    address target;
    bytes data;
}

// Usage:
// Copy value "debug_data" from the report.csv and: (long bytestring is example)
// RPC_URL=$RPC_URL forge script DebugFailure --ffi --sig "run(bytes)" 0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000015cb7ec0000000000000000000000009999999b8ce70322b021efe340759b7958af43c8000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a43927a5e700000000000000000000000008064a8eeecf71203449228f3eac65e462009fdf000000000000000000000000000000000000000000000d1e345dcfbf4bea000000000000000000000000000000000000000000000000000000238aaba8bbf38300000000000000000000000008ebfdb527eb9215e05cc5959aefaf68df0f7e760000000000000000

contract DebugFailure is Script {
    function run(bytes calldata args) public {
        DebugData memory debugData = abi.decode(args, (DebugData));
        string memory rpcUrl = vm.envString("RPC_URL");
        vm.createSelectFork(rpcUrl, debugData.preceedingBlocknumber);
        vm.deal(debugData.target, 10000 ether);
        (bool success, bytes memory result) = debugData.target.call(debugData.data);

        console.log("result:");
        console.logBytes(result);
        console.log("");

        if (success) {
            console.log("Call succeeded");
        } else {
            string[] memory ffiArgs = new string[](3);
            ffiArgs[0] = "cast";
            ffiArgs[1] = "4byte-decode";
            ffiArgs[2] = vm.toString(result);
            bytes memory decodedError = vm.ffi(ffiArgs);
            console.log("Decoded error:");
            console.log(string(decodedError));

            revert("Call failed");
        }
    }
}