// SPDX-License-Identifier: MIT
// The buyer waiting for cheap NFTs in the free-rider challenge: pays full
// price (15 ETH each) to whoever delivers an approved NFT.
pragma solidity ^0.8.0;

import {IERC721} from "../tokens/ERC721.sol";

contract FreeRiderBuyer {
    uint256 public constant NFT_PRICE = 15 ether;

    function buy(address nft, uint256 tokenId) external {
        payable(msg.sender).transfer(NFT_PRICE);
        IERC721(nft).transferFrom(msg.sender, address(this), tokenId);
    }

    receive() external payable {}
}
