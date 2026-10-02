// SPDX-License-Identifier: MIT
// The flash-loan "user" of the naive-receiver challenge: a borrower contract
// that dutifully repays loans plus the fixed fee from its own balance.
pragma solidity ^0.8.0;

import {NaiveReceiverPool} from "./NaiveReceiverPool.sol";
import {IFlashLoanReceiver} from "./NaiveReceiverPool.sol";

contract NaiveReceiverVictim is IFlashLoanReceiver {
    NaiveReceiverPool public immutable pool;

    constructor(address _pool) {
        pool = NaiveReceiverPool(payable(_pool));
    }

    // Repay the loan (received as msg.value) plus the fixed fee.
    function receiveEther(uint256 fee) external payable override {
        require(msg.sender == address(pool), "only pool");
        pool.deposit{value: msg.value + fee}();
    }

    receive() external payable {}
}
