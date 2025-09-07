// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {StateChangeHandlerGasEstimator} from "../src/StateChangeHandlerGasEstimator.sol";

contract DummyFallback {
    error BadError();
    event CallSuccess();

    function a() external {
        emit CallSuccess();
    }

    function b() external {
        revert BadError();
    }

}

contract StateChangeHandlerGasEstimatorTest is Test {
    error BadError();
    event CallSuccess();

    StateChangeHandlerGasEstimator public stateChangeHandlerGasEstimator;
    DummyFallback public dummyFallback;
    bytes dummyFallbackCode;

    function setUp() public {
        dummyFallback = new DummyFallback();
        dummyFallbackCode = address(dummyFallback).code;
        stateChangeHandlerGasEstimator = new StateChangeHandlerGasEstimator(dummyFallbackCode);
    }

    // function test_deploy_state_change_handler() public {
    //     stateChangeHandlerGasEstimator = new StateChangeHandlerGasEstimator(address(new DummyFallback()).code);
    // }

    function test_constructor_random_bytes(bytes memory randomDeploycode) public {
        vm.assume(randomDeploycode.length > 0);
        vm.assume(randomDeploycode.length < 2 ** 16);
        // lol: https://eips.ethereum.org/EIPS/eip-3541
        vm.assume(randomDeploycode[0] != 0xEF);

        stateChangeHandlerGasEstimator = new StateChangeHandlerGasEstimator(randomDeploycode);

        address fallbackImplAddress = stateChangeHandlerGasEstimator.fallbackImpl();
        assertTrue(fallbackImplAddress != address(0));

        bytes memory expectedCode = randomDeploycode;
        bytes memory actualCode = fallbackImplAddress.code;
        
        assertEq(actualCode, expectedCode);
    }

    function test_constructor_deploys_fallback_and_sets_address() public view {
        address fallbackImplAddress = stateChangeHandlerGasEstimator.fallbackImpl();
        assertTrue(fallbackImplAddress != address(0));

        bytes memory expectedCode = dummyFallbackCode;
        bytes memory actualCode = fallbackImplAddress.code;
        
        assertEq(actualCode, expectedCode);
    }

    function test_fallback_a() public {
        vm.expectEmit(address(stateChangeHandlerGasEstimator));
        emit CallSuccess();
        address(stateChangeHandlerGasEstimator).call(abi.encodeWithSelector(DummyFallback.a.selector));
    }

    function test_fallback_b() public {
        vm.expectRevert(abi.encodeWithSelector(DummyFallback.BadError.selector));
        address(stateChangeHandlerGasEstimator).call(abi.encodeWithSelector(DummyFallback.b.selector));
    }
}