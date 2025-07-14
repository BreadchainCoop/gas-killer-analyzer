// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract AccessControlTestMain {
    AccessControlA private a;

    constructor() {
        a = new AccessControlA(address(this));
    }

    function run() public {
        a.accessControlled();
    }
}

contract AccessControlA {
    address private caller;
    uint256 private counter;

    constructor (address _caller) {
        caller = _caller;
    }

    function accessControlled() public {
        require(msg.sender == caller, "Not authorized");
        counter++;
    }
}