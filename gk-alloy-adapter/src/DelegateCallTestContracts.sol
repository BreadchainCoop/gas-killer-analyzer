// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// State changes and whether they should be included for the StateChangeHandlerLib:
// ---
// main.sstore(toggle, !toggle) (Y)
// main.changeSomethingAndDelegatecall() (Y)
// main.a.sstore(value, value + 1) (N)
// main.a.delegatecall(DummyContractB.callToThisWithDelegatecall) (N)
// main.a.b.sstore(value, value * 2) (N)
// main.sstore(balance, balance + 1 ether) (Y)
// main.delegatecall(DummyContractC.delegateCallFromMain) (N)
// main.c.sstore(balance, balance + 2 ether) (Y)
// ---
// End results:
// 3 SSTOREs, 1 CALL
// toggle = true
// balance = 3 ether
// ---
contract DelegateCallTestMain {
    DelegateCallTestA public a;
    DelegateCallTestC public c;
    uint256 public balance;
    bool public toggle;

    constructor() {
        a = new DelegateCallTestA();
        c = new DelegateCallTestC();
    }

    function run() public {
        toggle = !toggle;
        a.changeSomethingAndDelegatecall();
        balance = balance + 1 ether;
        (bool success, ) = address(c).delegatecall(abi.encodeCall(DelegateCallTestC.delegateCallFromMain, ()));
        require(success, "Delegatecall failed");
    }
}

contract DelegateCallTestA {
    uint256 public value;
    DelegateCallTestB public b;

    function changeSomethingAndDelegatecall() public {
        value = value + 1;
        (bool success, ) = address(b).delegatecall(abi.encodeCall(DelegateCallTestB.callToThisWithDelegatecall, ()));
        require(success, "Delegatecall failed");
    }
}

contract DelegateCallTestB { 
    uint256 public value;
    DelegateCallTestB public b;

    function callToThisWithDelegatecall() public {
        value = value * 2;
    }
}

contract DelegateCallTestC {
    DelegateCallTestA public a;
    DelegateCallTestC public c;
    uint256 public balance;
    bool public toggle;

    function delegateCallFromMain() public {
        balance = balance + 2 ether;
    }
}