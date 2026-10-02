// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {PuppetPool} from "../../src/challenges/PuppetPool.sol";
import {PuppetAttacker} from "../../src/attackers/PuppetAttacker.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";
import {IUniswapV1Exchange, UniswapV1Factory} from "../../src/uniswap/UniswapV1.sol";

contract {{TEST_CONTRACT}} is Test {
    // Accept the drained loot + attacker's ETH refund.
    receive() external payable {}

    function test_agentSolve() public {
        address deployer = makeAddr("deployer");
        vm.deal(deployer, 100 ether);

        vm.startPrank(deployer);
        ERC20Mintable token = new ERC20Mintable("DVT", "DVT");
        token.mint(deployer, 2_000_000 ether);

        UniswapV1Factory factory = new UniswapV1Factory();
        IUniswapV1Exchange exchange = IUniswapV1Exchange(factory.createPair(address(token)));
        token.approve(address(exchange), 10 ether);
        exchange.addLiquidity{value: 10 ether}(1, 10 ether, block.timestamp + 1 days);

        PuppetPool pool = new PuppetPool(address(token), address(exchange), 2);
        token.transfer(address(pool), 100_000 ether);

        PuppetAttacker attacker = new PuppetAttacker(address(pool), address(exchange));
        // Fund the attacker from the deployer, who holds the supply.
        token.transfer(address(attacker), {{DUMP_TOKENS}});
        vm.stopPrank();

        deal(address(attacker), 1 ether);

        attacker.attack();

        assertEq(token.balanceOf(address(pool)), 0, "pool not drained");
        // The attacker transferred the loot to its owner (the test contract);
        // the dumped tokens are consumed crashing the oracle.
        assertGe(token.balanceOf(attacker.owner()), 100_000 ether, "no profit");
        console2.log("[PROFIT_WEI]", token.balanceOf(attacker.owner()));
    }
}
