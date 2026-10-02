// SPDX-License-Identifier: MIT
// Vulnerable LayerZero V1-style OApp — the second cross-chain challenge
// class: empty-peer bypass via the bytes32(0)→address(0) cast.
//
// BUG (V1 family): setTrustedRemote stores the full trusted path as bytes;
//   many deployed apps then validated with the equivalent of
//   `address(bytes20(_srcAddress << 96)) == remote` — which treats the zero
//   address as valid when _srcAddress is empty. An empty remote path
//   therefore authenticates ANY unconfigured source chain, and a forged
//   srcChainId with an empty path executes arbitrary payout instructions.
//   This is the exact shape behind several historical cross-chain thefts.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract LayerZeroOAppV1 {
    ERC20Mintable public immutable token;
    address public immutable owner;

    // srcChainId => trusted remote path (V1 style: bytes, 20-byte addr on EVM)
    mapping(uint16 => bytes) public trustedRemote;
    mapping(uint16 => mapping(bytes => uint64)) public inboundNonce;

    event Payout(address indexed to, uint256 amount);

    constructor(address _token) {
        token = ERC20Mintable(_token);
        owner = msg.sender;
    }

    function setTrustedRemote(uint16 srcChainId, bytes calldata path) external {
        require(msg.sender == owner, "only owner");
        trustedRemote[srcChainId] = path;
    }

    // V1-style inbound surface: (srcChainId, srcAddress, nonce, payload).
    function lzReceive(uint16 srcChainId, bytes calldata srcAddress, uint64 nonce, bytes calldata payload) external {
        // BUG: empty-path bypass — the cast makes bytes32(0) "valid" against
        // an unset mapping entry, so unconfigured chains authenticate as the
        // zero address. Comparison is also path-prefix-only (<< 96), which is
        // the permissive form several real apps shipped.
        bytes32 provided = bytes32(srcAddress);
        bytes32 remote = bytes32(trustedRemote[srcChainId]);
        require(provided << 96 == remote << 96, "untrusted remote");

        inboundNonce[srcChainId][srcAddress] = nonce; // never checked either

        // payload = abi.encode(recipient, amount): payment instruction.
        (address recipient, uint256 amount) = abi.decode(payload, (address, uint256));
        token.transfer(recipient, amount);
        emit Payout(recipient, amount);
    }

    function oAppVersion() external pure returns (uint64 senderVersion, uint64 receiverVersion) {
        return (1, 1);
    }
}
