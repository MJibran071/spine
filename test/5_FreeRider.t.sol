// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {FreeRiderPool} from "../src/challenges/FreeRiderPool.sol";
import {NaiveReceiverPool} from "../src/challenges/NaiveReceiverPool.sol";
import {FreeRiderBuyer} from "../src/challenges/FreeRiderBuyer.sol";
import {FreeRiderAttacker} from "../src/attackers/FreeRiderAttacker.sol";
import {ERC721} from "../src/tokens/ERC721.sol";

contract FreeRiderChallengeTest is Test {
    FreeRiderPool internal marketplace;
    NaiveReceiverPool internal lenderPool;
    FreeRiderBuyer internal buyer;
    FreeRiderAttacker internal attacker;
    ERC721 internal nft;
    address internal deployer;
    address internal attackerEoa;

    uint256[] internal tokenIds;
    uint256[] internal prices;

    uint256 internal constant NFT_PRICE = 15 ether;
    uint256 internal constant AMOUNT_OF_NFTS = 6;
    uint256 internal constant MARKETPLACE_INITIAL_ETH_BALANCE = 90 ether;
    uint256 internal constant LENDER_POOL_INITIAL_ETH_BALANCE = 1000 ether;
    uint256 internal constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        attackerEoa = makeAddr("attackerEoa");
        vm.deal(deployer, LENDER_POOL_INITIAL_ETH_BALANCE);

        vm.startPrank(deployer);
        nft = new ERC721("Free Rider NFT", "FRNFT");
        lenderPool = new NaiveReceiverPool();
        lenderPool.deposit{value: LENDER_POOL_INITIAL_ETH_BALANCE}();

        marketplace = new FreeRiderPool(address(nft));

        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) {
            nft.mint(deployer);
            tokenIds.push(i);
            prices.push(NFT_PRICE);
        }
        nft.setApprovalForAll(address(marketplace), true);
        marketplace.offerMany(tokenIds, prices);

        buyer = new FreeRiderBuyer();
        vm.stopPrank();

        // The buyer has ETH ready to repurchase the NFTs at full price.
        deal(address(buyer), AMOUNT_OF_NFTS * NFT_PRICE);
        // The marketplace holds the seller payout funds.
        deal(address(marketplace), MARKETPLACE_INITIAL_ETH_BALANCE);

        vm.deal(attackerEoa, PLAYER_INITIAL_ETH_BALANCE);
        vm.prank(attackerEoa);
        attacker = new FreeRiderAttacker(
            address(lenderPool), address(marketplace), address(nft), address(buyer), tokenIds
        );
    }

    function test_marketplaceHasNFTsListed() public view {
        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) {
            (bool isOffered, , ) = marketplace.offers(i);
            assertTrue(isOffered);
        }
    }

    function test_freeRiderDrain() public {
        vm.startPrank(attackerEoa);
        attacker.attack();
        vm.stopPrank();

        // Attacker ends with all 6 NFTs — delivered to the buyer.
        for (uint256 i = 0; i < AMOUNT_OF_NFTS; i++) {
            assertEq(nft.ownerOf(i), address(buyer), "buyer missing an NFT");
        }

        // Lender pool is repaid in full (15 loan + 1 fee).
        assertGe(address(lenderPool).balance, LENDER_POOL_INITIAL_ETH_BALANCE + 1 ether);

        // Attacker captured the resale profit: 90 collected - 16 repaid,
        // plus the 0.1 ETH seed it started with.
        assertEq(attackerEoa.balance, 74.1 ether, "attacker did not profit");
    }
}
