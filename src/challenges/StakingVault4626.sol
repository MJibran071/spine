// SPDX-License-Identifier: MIT
// Vulnerable ERC-4626-style staking vault.
//
// BUG (share inflation / donation attack): share price = totalAssets() /
// totalSupply() where totalAssets() is the raw token balance — direct
// donations count as yield. With no virtual-share offset, a first depositor
// can donate assets before depositing 1 wei, minting essentially the whole
// supply; every later depositor's share calc rounds down to zero shares, and
// their deposited assets are redeemable by the first depositor alone.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract StakingVault4626 {
    ERC20Mintable public immutable asset;
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    error OwnerOnly();

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);

    constructor(address _asset, string memory _name, string memory _symbol) {
        asset = ERC20Mintable(_asset);
        name = _name;
        symbol = _symbol;
    }

    // BUG: raw balance includes tokens donated straight to the vault.
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Rounding always favors the vault — which, combined with donation-
    // inflated totalAssets, rounds late depositors down to zero shares.
    function convertToShares(uint256 assets) public view returns (uint256 shares) {
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256 assets) {
        uint256 supply = totalSupply;
        assets = supply == 0 ? shares : (shares * totalAssets()) / supply;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function maxRedeem(address owner) external view returns (uint256) {
        return balanceOf[owner];
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        if (msg.sender != owner) revert OwnerOnly();
        assets = convertToAssets(shares);
        _burn(owner, shares);
        asset.transfer(receiver, assets);
        emit Withdraw(msg.sender, receiver, assets, shares);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
}
