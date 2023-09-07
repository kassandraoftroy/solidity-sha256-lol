// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {SHA256} from "../src/SHA256.sol";

contract SHA256Test is Test {
    SHA256 public sha;

    function setUp() public {
        sha = new SHA256();
    }

    function testHash() public {
        bytes32 x = sha.hash(bytes(""));
        assertEq(x, 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855);
       
        bytes32 y = sha.hash(bytes("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assertEq(y, 0x09f61f8d9cd65e6a0c258087c485b6293541364e42bd97b2d7936580c8aa3c54);

        bytes memory long = bytes("The quick brown fox jumps over the lazy dog");
        assertEq(sha.hash(long), sha256(long));
    }
}
