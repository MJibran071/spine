// SPDX-License-Identifier: MIT
// Vulnerable LayerZero OApp — CROSS-CHAIN SIGNATURE REPLAY (EIP-712 domain
// gap).
//
// BUG: the payout is authorized by an EIP-712 signature over (user, amount,
//   nonce) — but the digest does NOT bind the destination chain (block.chainid)
//   or this contract. A signature issued for Chain A's instance verifies
//   identically on Chain B's instance of the same app. An attacker who
//   observes (or obtains) one valid signature collects the payout on BOTH
//   chains. The per-user nonce lives in the same (unbound) storage on both
//   chains too, so the second chain has no independent replay protection.
//
// Historical class: signature reuse across chains / EIP-712 missing domain
// separation (challenge #17/#18: cross-chain signature replay).
pragma solidity ^0.8.0;

contract LayerZeroSigReplay {
    address public immutable owner;
    mapping(address => uint256) public userNonce;

    event Payout(address indexed to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {}

    function _digest(address user, uint256 amount, uint256 nonce) internal pure returns (bytes32) {
        // BUG: no block.chainid, no address(this) — the "domain" is universal.
        return keccak256(abi.encode(user, amount, nonce));
    }

    function claimPayout(uint256 amount, bytes calldata signature) external {
        uint256 nonce = userNonce[msg.sender]++;
        bytes32 digest = _digest(msg.sender, amount, nonce);
        // EIP-191 personal_sign recovery over the raw digest.
        bytes32 prefixed = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );
        (address signer, ) = _recover(prefixed, signature);
        require(signer == owner, "bad signature");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "payout failed");
        emit Payout(msg.sender, amount);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address, bytes32) {
        require(sig.length == 65, "bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return (ecrecover(digest, v, r, s), digest);
    }
}
