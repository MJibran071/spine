// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TrusterLenderPool} from "../../src/challenges/TrusterLenderPool.sol";
import {TrusterAttacker} from "../../src/attackers/TrusterAttacker.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        address deployer = makeAddr("deployer");
        vm.deal(deployer, 1 ether);

        vm.startPrank(deployer);
        ERC20Mintable token = new ERC20Mintable("DVT", "DVT");
        token.mint(deployer, 1_000_000 ether);
        TrusterLenderPool pool = new TrusterLenderPool(address(token));
        token.mint(address(pool), 1_000_000 ether);
        vm.stopPrank();

        TrusterAttacker attacker = new TrusterAttacker(address(pool));
        attacker.attack();

        assertEq(token.balanceOf(address(pool)), 0, "pool not drained");
        // The attacker transferred the loot to its owner (the test contract).
        assertGt(token.balanceOf(attacker.owner()), 0, "no profit");
        console2.log("[PROFIT_WEI]", token.balanceOf(attacker.owner()));
    }
}
