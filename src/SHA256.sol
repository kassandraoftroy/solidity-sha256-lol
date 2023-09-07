// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @notice NOT AUDITED
/// author: kassandra.eth
/// h/t to rage_pit for help on the input padding padding assembly bit
contract SHA256 {

    function hash(bytes memory value) external pure returns (bytes32 output) {
        (uint32[] memory words, uint256 rounds) = padInput(value);

        uint32[8] memory h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ];

        for (uint256 i=0; i<rounds; i++) {
            uint32[16] memory chunk = [
                words[i*16], words[i*16+1], words[i*16+2], words[i*16+3],
                words[i*16+4], words[i*16+5], words[i*16+6], words[i*16+7],
                words[i*16+8], words[i*16+9], words[i*16+10], words[i*16+11],
                words[i*16+12], words[i*16+13], words[i*16+14], words[i*16+15]
            ];
            h = round(chunk, h);
        }

        // pack h, 8 uint32 words, into a bytes32
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, shl(0xe0, mload(h)))
            mstore(add(ptr, 0x04), shl(0xe0, mload(add(h, 0x20))))
            mstore(add(ptr, 0x08), shl(0xe0, mload(add(h, 0x40))))
            mstore(add(ptr, 0x0c), shl(0xe0, mload(add(h, 0x60))))
            mstore(add(ptr, 0x10), shl(0xe0, mload(add(h, 0x80))))
            mstore(add(ptr, 0x14), shl(0xe0, mload(add(h, 0xa0))))
            mstore(add(ptr, 0x18), shl(0xe0, mload(add(h, 0xc0))))
            mstore(add(ptr, 0x1c), shl(0xe0, mload(add(h, 0xe0))))
            output := mload(ptr)
        }
    }

    // initial hashes = [
    //     0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    // ];
    function round(uint32[16] memory chunk, uint32[8] memory hashes) public pure returns (uint32[8] memory output)  {
        unchecked {
            uint32[64] memory w;
            for (uint256 n=0; n<16; n++){
                w[n] = chunk[n];
            }

            for (uint256 j=16; j<64; j++) {
                w[j] = w[j-16] + gamma0(w[j-15]) + w[j-7] + gamma1(w[j-2]);
            }

            uint32 a = hashes[0];
            uint32 b = hashes[1];
            uint32 c = hashes[2];
            uint32 d = hashes[3];
            uint32 e = hashes[4];
            uint32 f = hashes[5];
            uint32 g = hashes[6];
            uint32 h = hashes[7];

            uint32[64] memory k = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            ];
            for (uint256 i=0; i<64; i++) {
                uint32 temp1 = h + sigma1(e) + Ch(e,f,g) + k[i] + w[i];
                uint32 temp2 = sigma0(a) + Maj(a,b,c);
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            output = [
                hashes[0]+a,
                hashes[1]+b,
                hashes[2]+c,
                hashes[3]+d,
                hashes[4]+e,
                hashes[5]+f,
                hashes[6]+g,
                hashes[7]+h
            ];
        }
    }

    function padInput(bytes memory input) internal pure returns (uint32[] memory output, uint256 rounds) {
        // this part is from rage_pit
        assembly {
            let len := mload(input)
            let dataPtr := add(input, 0x20)
            // pad message with 0b1
            mstore(add(len, dataPtr), shl(0xf8, 0x80))

            // pad with zeros to nearest multiple of 64 bytes
            let pad := mod(len, 0x40)
            let k := add(len, sub(0x38, pad))
            switch lt(pad, 0x38)
                case 0 { k := add(k, 0x38) }

            //zero out to end of padding
            calldatacopy(add(dataPtr, add(len, 0x01)), calldatasize(), k)
            // end padding with message length
            mstore(add(k, dataPtr), shl(0xc0, mul(0x08, len)))

            // number of rounds
            rounds := add(div(k, 0x40), 0x01)
            
            // go to free memory
            let pushPtr := sub(add(k, 0x08), len)
            let fptr := mload(0x40)
            let free := add(fptr, pushPtr)
            
            // construct uint32[]
            mstore(free, 0x20)
            let entries := mul(rounds, 0x10)
            mstore(add(free, 0x20), entries)
            for {let i := 0} lt(i, entries) {i := add(i, 1)} {
                mstore(add(add(free, 0x20), mul(i, 0x20)), shr(0xe0, mload(add(dataPtr, mul(i, 0x04)))))
            }
            output := free

            // update free memory pointer
            mstore(0x40, add(add(free, 0x40), mul(entries, 0x20)))
        }
    }

    function sigma0(uint32 x) internal pure returns (uint32) {
        return (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22));
    }

    function sigma1(uint32 x) internal pure returns (uint32) {
        return (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25));
    }

    function gamma0(uint32 x) internal pure returns (uint32) {
       return (ROR(x, 7) ^ ROR(x, 18) ^ R(x, 3));
    }

    function gamma1(uint32 x) internal pure returns (uint32) {
        return (ROR(x, 17) ^ ROR(x, 19) ^ R(x, 10));
    }

    function R(uint32 x, uint32 n) internal pure returns (uint32) {
       return (x & 0xffffffff) >> n;
    }

    function ROR(uint32 x, uint32 y) internal pure returns (uint32) {
        return (((x & 0xffffffff) >> (y & 31)) | (x << (32 - (y & 31)))) & 0xffffffff;
    }

    function Ch(uint32 x, uint32 y, uint32 z) internal pure returns (uint32) {
        return (z ^ (x & (y ^ z)));
    }

    function Maj(uint32 x, uint32 y, uint32 z) internal pure returns (uint32) {
        return (((x | y) & z) | (x & y));
    }
}
