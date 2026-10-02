// SPDX-License-Identifier: MIT
// Vulnerable cross-chain bridge (real incident classes: incomplete signature
// binding + false deposits).
//
// BUG 1 (claim replay — the Ronin/Harmony family): a relayer signature binds
//   ONLY (txHash, amount). The claim id is (txHash, logIndex), and claim
//   submission is permissionless (anyone can relay). One broadcast signature
//   — and relayer broadcasts are public mempool objects — can therefore be
//   replayed under fresh logIndex values with an attacker-chosen recipient,
//   paying out again every time until the vault is empty. Threshold-1 hot
//   key means a single observed signature is enough.
// BUG 2 (false deposit — the Qubit class): the express/permit deposit path
//   credits `amount` for the destination chain without ever pulling the tokens
//   (the collateral transfer was never implemented). The bridge emits outbound
//   credits that nothing backs.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract CrossChainBridge {
    ERC20Mintable public immutable token;
    address public immutable relayer; // trusted validator (hot key, threshold 1)

    mapping(bytes32 => bool) public executed; // claimId => already paid
    mapping(uint256 => uint256) public outboundCredit; // depositId => credited amount

    event Deposited(address indexed depositor, uint256 indexed depositId, uint256 amount);
    event Claimed(bytes32 indexed txHash, uint256 indexed logIndex, address recipient, uint256 amount);

    error AlreadyExecuted();
    error BadSignature();
    error BadSignatureLength();

    constructor(address _token, address _relayer) {
        token = ERC20Mintable(_token);
        relayer = _relayer;
    }

    // Inbound (honest path): users "bridge out" by locking collateral; the
    // emitted event is what the destination chain mints against.
    function deposit(uint256 depositId, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        outboundCredit[depositId] += amount;
        emit Deposited(msg.sender, depositId, amount);
    }

    // Inbound (express path): meant to combine a token permit with the deposit
    // so users pay no separate approval tx.
    // BUG: the permit parsing and the collateral transfer were never
    // implemented — full credit for zero collateral (the Qubit incident).
    function depositWithPermitData(uint256 depositId, uint256 amount, bytes calldata permitData) external {
        permitData; // vestigial
        outboundCredit[depositId] += amount;
        emit Deposited(msg.sender, depositId, amount);
    }

    // Outbound claims: a relayer signature authorizes paying a source-chain
    // payout on this chain. Submission is permissionless; the signed message
    // binds (txHash, amount) but NOT logIndex nor recipient.
    function withdraw(bytes32 txHash, uint256 logIndex, address recipient, uint256 amount, bytes calldata sig)
        external
    {
        bytes32 claimId = keccak256(abi.encodePacked(txHash, logIndex));
        if (executed[claimId]) revert AlreadyExecuted();
        if (!_verifyRelayerSig(txHash, amount, sig)) revert BadSignature();
        executed[claimId] = true;
        token.transfer(recipient, amount);
        emit Claimed(txHash, logIndex, recipient, amount);
    }

    function _verifyRelayerSig(bytes32 txHash, uint256 amount, bytes calldata sig) internal view returns (bool) {
        if (sig.length != 65) revert BadSignatureLength();
        bytes32 messageHash = keccak256(abi.encode(txHash, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(digest, v, r, s) == relayer;
    }
}
