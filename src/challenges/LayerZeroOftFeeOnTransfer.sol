// SPDX-License-Identifier: MIT
// Vulnerable omnichain token (OFT-style) — FEE-ON-TRANSFER INFLATION
// (challenge #21).
//
// BUG: debitOFT tokens take a fee on every transfer. The bridge (a) debits
//   the user's LOCAL balance by the REQUESTED amount (not the amount actually
//   received by the contract) and (b) credits the destination with that same
//   requested amount. Every hop therefore creates value out of nothing:
//   source keeps the fee's underlying tokens AND the destination mints the
//   full requested amount. Repeated transfers inflate total supply.
//
// The honest invariant: source debit = destination credit + documented dust;
// a fee-on-transfer token must be rejected or handled by crediting only the
// amount actually received (balance-delta accounting).
pragma solidity ^0.8.0;

contract FeeOnTransferToken {
    string public constant name = "Fee Token";
    string public constant symbol = "FOT";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    uint256 public constant FEE_BPS = 500; // 5% transfer fee
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 received = amount - fee;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += received; // the fee is simply destroyed
        totalSupply -= fee;
        emit Transfer(msg.sender, to, received);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        uint256 fee = (amount * FEE_BPS) / 10_000;
        uint256 received = amount - fee;
        balanceOf[from] -= amount;
        balanceOf[to] += received;
        totalSupply -= fee;
        emit Transfer(from, to, received);
        return true;
    }
}

contract LayerZeroOftFeeOnTransfer {
    FeeOnTransferToken public immutable token;
    address public immutable owner;
    address public immutable endpoint; // only the endpoint may deliver

    // destination-side ledger of bridged-in credits
    mapping(address => uint256) public bridgedCredit;
    // source-side ledger of bridged-out debits (REQUESTED amounts!)
    mapping(address => uint256) public bridgedDebit;

    event BridgedOut(address indexed from, uint256 requestedAmount);
    event BridgedIn(address indexed to, uint256 requestedAmount);

    constructor(address _token, address _endpoint) {
        token = FeeOnTransferToken(_token);
        owner = msg.sender;
        endpoint = _endpoint;
    }

    // SOURCE side: debit the user by the REQUESTED amount, emit the outbound
    // message. BUG: uses amount, not the balance delta the contract received.
    function bridgeOut(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        require(token.transferFrom(msg.sender, address(this), amount), "transferFrom failed");
        uint256 received = token.balanceOf(address(this)) - before;
        bridgedDebit[msg.sender] += amount; // <-- inflated: fee was destroyed, not bridged
        emit BridgedOut(msg.sender, amount);
        received; // the honest fix would use `received`; kept to expose the bug
    }

    // DESTINATION side: mint the full REQUESTED amount to the recipient.
    // Only the endpoint may deliver messages (the accounting bug is the
    // target here — see the endpoint-impersonation challenge for delivery
    // authorization itself).
    function bridgeIn(address to, uint256 requestedAmount) external {
        require(msg.sender == endpoint, "only endpoint");
        bridgedCredit[to] += requestedAmount;
        token.mint(to, requestedAmount); // <-- mints value the source never held
        emit BridgedIn(to, requestedAmount);
    }
}
