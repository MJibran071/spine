// SPDX-License-Identifier: MIT
// Minimal Uniswap V1-style AMM (factory + exchange) for the puppet challenge.
// Faithful to the flows the challenge needs: createPair, setup, addLiquidity,
// constant-product input swaps with a 0.3% fee. Direct ETH sends revert —
// use ethToTokenSwapInput.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

interface IUniswapV1Exchange {
    function tokenAddress() external view returns (address);
    function tokenPool() external view returns (uint256);
    function setup(address tokenAddress) external;
    function addLiquidity(uint256 min_liquidity, uint256 max_tokens, uint256 deadline)
        external payable returns (uint256);
    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline) external payable returns (uint256);
    function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline)
        external returns (uint256);
    function getEthToTokenInputPrice(uint256 eth_sold) external view returns (uint256);
    function getTokenToEthInputPrice(uint256 tokens_sold) external view returns (uint256);
}

interface IUniswapV1Factory {
    function createPair(address token) external returns (address);
    function getPair(address token) external view returns (address);
}

contract UniswapV1Exchange is IUniswapV1Exchange {
    address public immutable factory;
    address public tokenAddress;
    bool public initialized;

    uint256 public totalLiquidity;
    mapping(address => uint256) public liquidityOf;

    event TokenPurchase(address indexed buyer, uint256 eth_sold, uint256 tokens_bought);
    event EthPurchase(address indexed buyer, uint256 tokens_sold, uint256 eth_bought);
    event AddLiquidity(address indexed provider, uint256 eth_amount, uint256 token_amount);

    constructor(address _factory) {
        factory = _factory;
    }

    function setup(address _tokenAddress) external {
        require(msg.sender == factory, "only factory");
        require(!initialized, "already initialized");
        tokenAddress = _tokenAddress;
        initialized = true;
    }

    receive() external payable {
        revert("use ethToTokenSwapInput");
    }

    function addLiquidity(uint256 min_liquidity, uint256 max_tokens, uint256 deadline)
        external payable returns (uint256 liquidity_minted)
    {
        require(deadline > block.timestamp && msg.value > 0, "bad liquidity input");
        ERC20Mintable token = ERC20Mintable(tokenAddress);
        uint256 ethPool = address(this).balance;

        if (totalLiquidity == 0) {
            // First provider sets the exchange rate.
            liquidity_minted = msg.value;
            require(token.transferFrom(msg.sender, address(this), max_tokens), "token transfer failed");
            tokenPool = max_tokens;
        } else {
            ethPool -= msg.value;
            liquidity_minted = msg.value * totalLiquidity / ethPool;
            require(liquidity_minted >= min_liquidity, "price impact too high");
            uint256 token_amount = max_tokens * msg.value / ethPool;
            require(token_amount > 0, "zero token amount");
            require(token.transferFrom(msg.sender, address(this), token_amount), "token transfer failed");
            tokenPool += token_amount;
        }

        totalLiquidity += liquidity_minted;
        liquidityOf[msg.sender] += liquidity_minted;
        emit AddLiquidity(msg.sender, msg.value, tokenPool);
    }

    uint256 public tokenPool; // kept public for the challenge's reserve math

    function getEthToTokenInputPrice(uint256 eth_sold) public view returns (uint256) {
        require(eth_sold > 0, "zero input");
        uint256 ethPool = address(this).balance;
        require(ethPool > 0 && tokenPool > 0, "empty pool");
        uint256 eth_sold_with_fee = eth_sold * 997;
        return (tokenPool * eth_sold_with_fee) / (ethPool * 1000 + eth_sold_with_fee);
    }

    function getTokenToEthInputPrice(uint256 tokens_sold) public view returns (uint256) {
        require(tokens_sold > 0, "zero input");
        uint256 ethPool = address(this).balance;
        require(ethPool > 0 && tokenPool > 0, "empty pool");
        uint256 tokens_sold_with_fee = tokens_sold * 997;
        return (ethPool * tokens_sold_with_fee) / (tokenPool * 1000 + tokens_sold_with_fee);
    }

    function ethToTokenSwapInput(uint256 min_tokens, uint256 deadline)
        external payable returns (uint256 tokens_bought)
    {
        require(deadline > block.timestamp, "expired");
        tokens_bought = getEthToTokenInputPrice(msg.value);
        require(tokens_bought >= min_tokens, "slippage");
        tokenPool -= tokens_bought;
        require(ERC20Mintable(tokenAddress).transfer(msg.sender, tokens_bought), "transfer failed");
        emit TokenPurchase(msg.sender, msg.value, tokens_bought);
    }

    function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline)
        external returns (uint256 eth_bought)
    {
        require(deadline > block.timestamp, "expired");
        eth_bought = getTokenToEthInputPrice(tokens_sold);
        require(eth_bought >= min_eth, "slippage");
        require(ERC20Mintable(tokenAddress).transferFrom(msg.sender, address(this), tokens_sold), "transferFrom failed");
        tokenPool += tokens_sold;
        payable(msg.sender).transfer(eth_bought);
        emit EthPurchase(msg.sender, tokens_sold, eth_bought);
    }
}

contract UniswapV1Factory is IUniswapV1Factory {
    mapping(address => address) public override getPair;
    address[] public allPairs;

    event PairCreated(address indexed token, address exchange);

    function createPair(address token) external returns (address) {
        require(token != address(0), "zero token");
        require(getPair[token] == address(0), "pair exists");
        UniswapV1Exchange exchange = new UniswapV1Exchange(address(this));
        exchange.setup(token);
        getPair[token] = address(exchange);
        allPairs.push(address(exchange));
        emit PairCreated(token, address(exchange));
        return address(exchange);
    }
}
