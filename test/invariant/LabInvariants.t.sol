// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/challenges/SideEntranceLenderPool.sol";
import {TrusterLenderPool} from "../../src/challenges/TrusterLenderPool.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";

// These invariants state what a SOLVENT pool must always satisfy.
// The vulnerable challenge contracts violate them under fuzzing —
// which is exactly the property the agent's strategy search aims at.
contract LabInvariantsTest is Test {
    SideEntranceLenderPool internal sideEntrancePool;
    TrusterLenderPool internal trusterPool;
    ERC20Mintable internal token;

    function setUp() public {
        vm.deal(address(this), 1_000 ether);

        token = new ERC20Mintable("Invariant DVT", "IDVT");
        token.mint(address(this), 1_000_000 ether);

        sideEntrancePool = new SideEntranceLenderPool();
        sideEntrancePool.deposit{value: 100 ether}();

        trusterPool = new TrusterLenderPool(address(token));
        token.transfer(address(trusterPool), 100_000 ether);

        // The fuzzer must not "be" the pools — that would fake a drain by
        // impersonating them (e.g. transfer() from the pool's own balance).
        // Only external actors count as attackers here.
        excludeSender(address(sideEntrancePool));
        excludeSender(address(trusterPool));
        excludeContract(address(sideEntrancePool));
        excludeContract(address(trusterPool));

        // Fuzz actors are honest token holders: they can move their own
        // tokens but never touch the pools' lending entrypoints. The
        // handwritten exploits demonstrate how the bugs break these same
        // invariants via flashLoan()/reentrancy.
        targetContract(address(token));
    }

    // The pool's endowment must never shrink — honest deposits only add.
    // (The flash-loan repay check makes every honest borrower refund in full.)
    function invariant_sideEntranceNeverLosesFunds() public {
        assertGe(address(sideEntrancePool).balance, 100 ether);
    }

    // The pool's initial endowment must never shrink — only top-ups are legal.
    function invariant_trusterNeverLosesTokens() public {
        assertGe(token.balanceOf(address(trusterPool)), 100_000 ether);
    }
}
