// SPDX-License-Identifier: MIT
// Interfaces for the local Uniswap V2 pair clone and the oracle targets.
pragma solidity ^0.8.0;

interface IUniswapV2PairLocal {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity);
    function price0CumulativeLast() external view returns (uint256);
    function price1CumulativeLast() external view returns (uint256);
}

interface IUniswapV2CalleeLocal {
    function uniswapV2Call(address sender, uint256 amount0Out, uint256 amount1Out, bytes calldata data) external;
}
