// SPDX-License-Identifier: MIT
// Vulnerable OFT — SHARED-DECIMAL DUST INFLATION (challenge #19 + #33).
//
// Real OFTs convert between a token's LOCAL decimals (18 for most) and a
// SHARED decimal floor (typically 6, so 6- and 18-decimal assets interop):
//   amountSD = amountLD / 10^(ld - sd)     (must round DOWN, dust dropped)
//   amountLD = amountSD * 10^(ld - sd)
//
// BUG: this implementation ROUNDS UP in _ld2sd. Every sub-unit remainder is
// rounded to a FULL shared unit and credited on destination. Two exploits:
//   (a) SPAM: bridging 0.0000000001 tokens (1e11 ld, below one shared unit)
//       rounds up to 1 full shared unit — 10_000x the value minted per hop.
//   (b) RESIDUE: any amount whose 12 low bits are nonzero gains ~1 unit.
// Each full loop mints value the source never burned → cross-chain supply
// inflation. The honest invariant: source debit = destination credit +
// explicitly documented (dropped) dust; rounding must be DOWN.
//
// This is the decimal-conversion half of the OFT threat model (#19), which
// composes with the fee-on-transfer half (#21) trained separately.
pragma solidity ^0.8.0;

contract SixDecimalToken {
    string public constant name = "Six Decimals";
    string public constant symbol = "SIX";
    uint8 public constant decimals = 6;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public minters;

    constructor() {
        minters[msg.sender] = true;
    }

    function setMinter(address m) external {
        // test fixture: open mint authority so harnesses can fund users
        minters[m] = true;
    }

    function mint(address to, uint256 amount) external {
        require(minters[msg.sender], "not minter");
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == from, "burn your own tokens");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}

contract LayerZeroOftDecimalDust {
    SixDecimalToken public immutable token;
    address public immutable endpoint;
    uint8 public constant LOCAL_DECIMALS = 18;
    uint8 public constant SHARED_DECIMALS = 6;
    uint256 public constant LD_PER_SD = 10 ** (LOCAL_DECIMALS - SHARED_DECIMALS); // 1e12

    // ledger of cross-chain value, in SHARED units (like real OFT accounting)
    mapping(address => uint256) public bridgedDebit;
    mapping(address => uint256) public bridgedCredit;

    event BridgedOut(address indexed from, uint256 amountSD);
    event BridgedIn(address indexed to, uint256 amountSD);

    constructor(address _token, address _endpoint) {
        token = SixDecimalToken(_token);
        endpoint = _endpoint;
        token.setMinter(address(this)); // destination-side mint authority
    }

    // BUG: round UP. A correct OFT divides (rounds down) and documents the
    // dropped dust; rounding up credits a full unit per sub-unit remainder.
    function _ld2sd(uint256 amountLD) internal pure returns (uint256) {
        return (amountLD + LD_PER_SD - 1) / LD_PER_SD; // <-- ceil instead of floor
    }

    // SOURCE side: pull the exact local amount and burn it, credit the
    // rounded-UP shared amount to the outbound message.
    function bridgeOut(uint256 amountLD) external {
        require(token.transferFrom(msg.sender, address(this), amountLD), "transferFrom failed");
        token.burn(address(this), amountLD);
        uint256 amountSD = _ld2sd(amountLD);
        bridgedDebit[msg.sender] += amountSD; // <-- inflated by up to 1 unit per call
        emit BridgedOut(msg.sender, amountSD);
    }

    // DESTINATION side: mint the FULL shared unit back to local decimals.
    // Only the endpoint may deliver (the conversion bug is the target here).
    function bridgeIn(address to, uint256 amountSD) external {
        require(msg.sender == endpoint, "only endpoint");
        bridgedCredit[to] += amountSD;
        token.mint(to, amountSD * LD_PER_SD); // <-- mints the rounded-up units
        emit BridgedIn(to, amountSD);
    }
}
