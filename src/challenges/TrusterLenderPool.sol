// SPDX-License-Identifier: MIT
// Vulnerable flash-lending pool (Damn Vulnerable DeFi-style).
// BUG: the flash loan makes an arbitrary low-level call to a borrower-chosen
// target with borrower-chosen data, so a loan of 0 lets the attacker call
// token.approve(spender, amount) AS the pool and walk away with everything.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract TrusterLenderPool {
    ERC20Mintable public immutable damnValuableToken;
    uint256 public constant MAX_FLASH_LOAN = 1_000_000 ether;

    error NotEnoughTokensInPool();
    error CallerMustBeContract();

    constructor(address tokenAddress) {
        damnValuableToken = ERC20Mintable(tokenAddress);
    }

    function maxFlashLoan() external view returns (uint256) {
        return MAX_FLASH_LOAN;
    }

    function flashLoan(uint256 borrowAmount, address borrower, address target, bytes calldata data)
        external
    {
        uint256 balanceBefore = damnValuableToken.balanceOf(address(this));
        require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

        require(target != address(this), "target cannot be the pool");
        require(borrower == msg.sender, "borrower must be caller");
        (bool success, ) = target.call(data);
        require(success, "External call failed");

        uint256 balanceAfter = damnValuableToken.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "flash loan not repaid");
    }
}
