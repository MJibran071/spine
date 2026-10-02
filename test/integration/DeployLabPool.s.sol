// SPDX-License-Identifier: MIT
// Integration fixture: deploys a vulnerable pool with 10 ETH onto a LOCAL
// chain so the agent's fork mode + approval gate can be tested end-to-end.
pragma solidity ^0.8.0;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {SideEntranceLenderPool} from "../../src/challenges/SideEntranceLenderPool.sol";

contract DeployLabPool is Script {
    function run() external {
        vm.startBroadcast();
        SideEntranceLenderPool pool = new SideEntranceLenderPool();
        pool.deposit{value: 10 ether}();
        vm.stopBroadcast();
        console2.log("poolAddr:", address(pool));
    }
}
