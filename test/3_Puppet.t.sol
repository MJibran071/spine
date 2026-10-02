// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {PuppetPool} from "../src/challenges/PuppetPool.sol";
import {PuppetAttacker} from "../src/attackers/PuppetAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";
import {IUniswapV1Exchange, UniswapV1Factory} from "../src/uniswap/UniswapV1.sol";

contract PuppetChallengeTest is Test {
    PuppetPool internal pool;
    PuppetAttacker internal attacker;
    ERC20Mintable internal token;
    IUniswapV1Exchange internal exchange;
    address internal deployer;
    address internal attackerEoa;

    uint256 internal constant TOKEN_INITIAL_SUPPLY = 2_000_000 ether; // 2M
    uint256 internal constant POOL_INITIAL_TOKEN_BALANCE = 100_000 ether;
    uint256 internal constant ATTACKER_INITIAL_TOKEN_BALANCE = 25_000 ether;
    uint256 internal constant ATTACKER_INITIAL_ETH_BALANCE = 1 ether;
    uint256 internal constant UNISWAP_INITIAL_TOKEN_RESERVE = 10 ether;
    uint256 internal constant UNISWAP_INITIAL_ETH_RESERVE = 10 ether;
    uint256 internal constant BORROWING_FACTOR = 2;

    function setUp() public {
        deployer = makeAddr("deployer");
        attackerEoa = makeAddr("attackerEoa");
        vm.deal(deployer, 100 ether);

        vm.startPrank(deployer);
        token = new ERC20Mintable("Damn Valuable Token", "DVT");
        token.mint(deployer, TOKEN_INITIAL_SUPPLY);

        UniswapV1Factory factory = new UniswapV1Factory();
        exchange = IUniswapV1Exchange(factory.createPair(address(token)));

        token.approve(address(exchange), UNISWAP_INITIAL_TOKEN_RESERVE);
        exchange.addLiquidity{value: UNISWAP_INITIAL_ETH_RESERVE}(
            1, UNISWAP_INITIAL_TOKEN_RESERVE, block.timestamp + 1 days
        );
        // Sanity: 1 token sells for ~0.907 ETH on the fresh 10:10 pair.
        assertApproxEqAbs(exchange.getTokenToEthInputPrice(10 ** 18), 9 * 10 ** 17, 0.02 ether);

        pool = new PuppetPool(address(token), address(exchange), BORROWING_FACTOR);
        token.transfer(address(pool), POOL_INITIAL_TOKEN_BALANCE);
        vm.stopPrank();

        vm.prank(attackerEoa);
        attacker = new PuppetAttacker(address(pool), address(exchange));
        // The attacker needs tokens to dump and ETH for collateral.
        vm.startPrank(deployer);
        token.transfer(address(attacker), ATTACKER_INITIAL_TOKEN_BALANCE);
        vm.stopPrank();
        deal(address(attacker), ATTACKER_INITIAL_ETH_BALANCE);
    }

    function test_poolHasInitialTokenBalance() public view {
        assertEq(token.balanceOf(address(pool)), POOL_INITIAL_TOKEN_BALANCE);
    }

    function test_oracleManipulationDrain() public {
        // Sanity: before manipulation, collateral for the whole pool is ~200 ETH.
        uint256 preDeposit = pool.computeOraclePrice();
        assertGt(preDeposit, 0);

        vm.startPrank(attackerEoa);
        attacker.attack();
        vm.stopPrank();

        // The pool holds no tokens; the attacker holds them all. The 25k
        // tokens used to crash the oracle are the attacker's cost of business.
        assertEq(token.balanceOf(address(pool)), 0, "pool tokens not drained");
        assertEq(token.balanceOf(attackerEoa), POOL_INITIAL_TOKEN_BALANCE,
            "attacker did not capture pool tokens");
    }
}
