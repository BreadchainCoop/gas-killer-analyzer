// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract DelegateCallWrapper {
    function delegatecall(address target, bytes memory data) public returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, string(result));
        return result;
    }
}