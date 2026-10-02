// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IFreeRiderPool {
    function buyMany(uint256[] calldata tokenIds) external payable;
    function offerMany(uint256[] calldata tokenIds, uint256[] calldata prices) external;
    function offers(uint256 tokenId) external view returns (bool isOffered, uint256 price, address seller);
}

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}
