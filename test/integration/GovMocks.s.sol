// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

/// @dev Minimal Safe-compatible contract: answers getOwners()/getThreshold().
contract MockSafe {
    address[] private _owners;
    uint256 private _threshold;

    constructor(address[] memory owners_, uint256 threshold_) {
        _owners = owners_;
        _threshold = threshold_;
    }

    function getOwners() external view returns (address[] memory) {
        return _owners;
    }

    function getThreshold() external view returns (uint256) {
        return _threshold;
    }
}

/// @dev EIP-1967 proxy storing an admin in the canonical admin slot.
contract MockEip1967AdminProxy {
    // keccak256("eip1967.proxy.admin") - 1
    bytes32 private constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    constructor(address admin) {
        assembly {
            sstore(ADMIN_SLOT, admin)
        }
    }
}

/// @dev Compound-style timelock answering admin() and delay().
contract MockCompoundTimelock {
    address public admin;
    uint256 public delay;

    constructor() {
        admin = msg.sender;
        delay = 900; // 15 min — below the 1h risk line
    }
}

contract DeployGovMocks is Test {
    function run() external returns (address safeProxy, address timelock) {
        vm.startBroadcast();
        address[] memory owners = new address[](2);
        owners[0] = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // anvil account 0 (EOA)
        owners[1] = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // anvil account 1 (EOA)
        MockSafe safe = new MockSafe(owners, 1); // threshold 1 — should trigger risks
        MockEip1967AdminProxy proxy = new MockEip1967AdminProxy(address(safe));
        safeProxy = address(proxy);
        timelock = address(new MockCompoundTimelock());
        vm.stopBroadcast();
    }
}
