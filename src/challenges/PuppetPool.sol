// SPDX-License-Identifier: MIT
// Vulnerable lending pool (Damn Vulnerable DeFi-style).
// BUG: collateral price derives from the Uniswap V1 pair's spot ratio, so a
// big single-trade dump of the token wrecks the oracle and lets an attacker
// borrow the whole pool's tokens with almost no collateral.
pragma solidity ^0.8.0;

import {IPuppetPool} from "../interfaces/IPuppetPool.sol";
import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";
import {IUniswapV1Exchange} from "../uniswap/UniswapV1.sol";

contract PuppetPool is IPuppetPool {
    mapping(address => uint256) public deposits;
    uint256 public borrowingFactor;

    address public immutable override token;
    address public immutable override uniswapPair;

    event Borrow(address indexed account, uint256 amount);

    error NotEnoughCollateral();

    constructor(address tokenAddress, address uniswapPairAddress, uint256 initialBorrowingFactor) {
        token = tokenAddress;
        uniswapPair = uniswapPairAddress;
        borrowingFactor = initialBorrowingFactor;
    }

    function deposit() external payable override {
        deposits[msg.sender] += msg.value;
    }

    function borrow(uint256 borrowAmount) external payable override {
        uint256 depositRequired = _computeDepositRequired(borrowAmount);

        if (msg.value < depositRequired) {
            revert NotEnoughCollateral();
        }

        if (msg.value > depositRequired) {
            payable(msg.sender).transfer(msg.value - depositRequired);
        }

        deposits[msg.sender] += depositRequired;
        ERC20Mintable(token).transfer(msg.sender, borrowAmount);

        emit Borrow(msg.sender, borrowAmount);
    }

    // Oracle: ETH per token, straight off the AMM's spot reserves. A big
    // token dump crashes this price (more tokens, less ETH in the pair).
    function computeOraclePrice() public view override returns (uint256) {
        address pair = uniswapPair;
        return address(pair).balance * 10 ** 18 / IUniswapV1Exchange(pair).tokenPool();
    }

    function _computeDepositRequired(uint256 borrowAmount) internal view returns (uint256) {
        return borrowAmount * borrowingFactor * computeOraclePrice() / 10 ** 18;
    }
}
