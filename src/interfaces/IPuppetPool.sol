// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPuppetPool {
    function computeOraclePrice() external view returns (uint256);
    function borrow(uint256 borrowAmount) external payable;
    function deposit() external payable;
    function token() external view returns (address);
    function uniswapPair() external view returns (address);
    function borrowingFactor() external view returns (uint256);
}
