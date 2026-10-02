// SPDX-License-Identifier: MIT
// Vulnerable NFT marketplace (Damn Vulnerable DeFi-style).
// BUG: buyMany charges the FULL original price for every NFT in the batch
// instead of the cumulative sum, so the last NFT is effectively free — and it
// pays the seller per item while only checking total msg.value once.
pragma solidity ^0.8.0;

import {IFreeRiderPool} from "../interfaces/IFreeRiderPool.sol";
import {ERC721} from "../tokens/ERC721.sol";

contract FreeRiderPool is IFreeRiderPool {
    struct Offer {
        bool isOffered;
        uint256 price;
        address seller;
    }

    mapping(uint256 => Offer) public override offers;
    mapping(uint256 => address) private _sellers;

    uint256 public nextPurchaseId;
    mapping(uint256 => uint256) public purchaseAmounts;

    ERC721 public immutable nft;

    event NFTBought(address indexed buyer, uint256 indexed tokenId, uint256 paidPrice);

    error NotEnoughToken();
    error TokenNotOffered();

    constructor(address _nft) {
        nft = ERC721(_nft);
    }

    function offerMany(uint256[] calldata tokenIds, uint256[] calldata prices) external override {
        require(tokenIds.length > 0 && tokenIds.length == prices.length, "bad input");
        for (uint256 i = 0; i < tokenIds.length; i++) {
            _offerOne(tokenIds[i], prices[i]);
        }
    }

    function _offerOne(uint256 tokenId, uint256 price) private {
        require(price > 0, "price must be > 0");
        nft.transferFrom(msg.sender, address(this), tokenId);
        offers[tokenId] = Offer({isOffered: true, price: price, seller: msg.sender});
    }

    function buyMany(uint256[] calldata tokenIds) external payable override {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            Offer storage offer = offers[tokenIds[i]];
            require(offer.isOffered, "NFT not offered for sale");
            // BUG (1): msg.value is checked against EACH item's price — it
            // carries over across iterations, so one price pays for all.
            require(msg.value >= offer.price, "Amount paid is not enough");

            offer.isOffered = false;
            nft.transferFrom(address(this), msg.sender, tokenIds[i]);
            // BUG (2): the seller is paid from the pool's funds, not from
            // escrowed buyer money.
            payable(offer.seller).transfer(offer.price);
            emit NFTBought(msg.sender, tokenIds[i], offer.price);
        }
    }

    // Records how much was charged for a purchase id (used by recovery flows).
    function recordPurchase(uint256 amount) external returns (uint256 purchaseId) {
        purchaseId = nextPurchaseId++;
        purchaseAmounts[purchaseId] = amount;
    }
}
