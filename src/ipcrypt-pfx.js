import { expandKey, subBytes, shiftRows, mixColumns } from './core/aes.js';
import { ipToBytes, bytesToIp } from './utils.js';

/**
 * Perform AES-128 encryption on a 16-byte block
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} input - 16-byte input block
 * @returns {Uint8Array} 16-byte encrypted block
 */
function aesEncrypt(key, input) {
    const state = new Uint8Array(input);
    const expandedKey = expandKey(key);

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[i];
    }

    // Main rounds
    for (let round = 1; round < 10; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[round * 16 + i];
        }
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[160 + i];
    }

    return state;
}

/**
 * Check if IP address is IPv4 based on 16-byte representation.
 * @param {Uint8Array} bytes16 - 16-byte IP representation
 * @returns {boolean} True if IPv4
 */
function isIPv4(bytes16) {
    return bytes16.slice(0, 10).every(b => b === 0) &&
        bytes16[10] === 0xff && bytes16[11] === 0xff;
}

/**
 * Extract bit at position from 16-byte array.
 * Position: 0 = LSB of byte 15, 127 = MSB of byte 0
 * @param {Uint8Array} data - 16-byte array
 * @param {number} position - Bit position (0-127)
 * @returns {number} Bit value (0 or 1)
 */
function getBit(data, position) {
    const byteIndex = 15 - Math.floor(position / 8);
    const bitIndex = position % 8;
    return (data[byteIndex] >> bitIndex) & 1;
}

/**
 * Set bit at position in 16-byte array.
 * Position: 0 = LSB of byte 15, 127 = MSB of byte 0
 * @param {Uint8Array} data - 16-byte array to modify
 * @param {number} position - Bit position (0-127)
 * @param {number} value - Bit value (0 or 1)
 */
function setBit(data, position, value) {
    const byteIndex = 15 - Math.floor(position / 8);
    const bitIndex = position % 8;

    if (value) {
        data[byteIndex] |= (1 << bitIndex);
    } else {
        data[byteIndex] &= ~(1 << bitIndex);
    }
}

/**
 * Shift a 16-byte array one bit to the left.
 * The most significant bit is lost, and a zero bit is shifted in from the right.
 * @param {Uint8Array} data - 16-byte array
 * @returns {Uint8Array} New shifted array
 */
function shiftLeftOneBit(data) {
    const result = new Uint8Array(16);
    let carry = 0;

    // Process from least significant byte (byte 15) to most significant (byte 0)
    for (let i = 15; i >= 0; i--) {
        // Current byte shifted left by 1, with carry from previous byte
        result[i] = ((data[i] << 1) | carry) & 0xFF;
        // Extract the bit that will be carried to the next byte
        carry = (data[i] >> 7) & 1;
    }

    return result;
}

/**
 * Pad prefix for prefix_len_bits=0 (IPv6).
 * Sets separator bit at position 0 (LSB of byte 15).
 * @returns {Uint8Array} Padded prefix
 */
function padPrefix0() {
    const padded = new Uint8Array(16);
    padded[15] = 0x01; // Set bit at position 0 (LSB of byte 15)
    return padded;
}

/**
 * Pad prefix for prefix_len_bits=96 (IPv4).
 * Result: 00000001 00...00 0000ffff (separator at pos 96, then 96 bits)
 * @returns {Uint8Array} Padded prefix
 */
function padPrefix96() {
    const padded = new Uint8Array(16);
    padded[3] = 0x01;  // Set bit at position 96 (bit 0 of byte 3)
    padded[14] = 0xFF;
    padded[15] = 0xFF;
    return padded;
}

/**
 * Encrypt an IP address using ipcrypt-pfx.
 * @param {string} ip - IP address string (IPv4 or IPv6)
 * @param {Uint8Array} key - 32-byte encryption key
 * @returns {string} Encrypted IP address string
 * @throws {Error} If key is invalid or halves are identical
 */
export function encrypt(ip, key) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }

    // Split the key into two AES-128 keys
    const K1 = key.slice(0, 16);
    const K2 = key.slice(16, 32);

    // Check that K1 and K2 are different
    if (K1.every((byte, i) => byte === K2[i])) {
        throw new Error('The two halves of the key must be different');
    }

    // Convert IP to 16-byte representation
    const bytes16 = ipToBytes(ip);

    // Initialize encrypted result with zeros
    const encrypted = new Uint8Array(16);

    // Determine starting point
    const ipv4 = isIPv4(bytes16);
    const prefixStart = ipv4 ? 96 : 0;

    // If IPv4, copy the IPv4-mapped prefix
    if (ipv4) {
        encrypted.set(bytes16.slice(0, 12), 0);
    }

    // No need to create cipher objects - we'll use aesEncrypt directly

    // Initialize padded_prefix for the starting prefix length
    let paddedPrefix;
    if (ipv4) {
        paddedPrefix = padPrefix96();
    } else {
        paddedPrefix = padPrefix0();
    }

    // Process each bit position
    for (let prefixLenBits = prefixStart; prefixLenBits < 128; prefixLenBits++) {
        // Compute pseudorandom function with dual AES encryption
        const e1 = aesEncrypt(K1, paddedPrefix);
        const e2 = aesEncrypt(K2, paddedPrefix);

        // XOR the two encryptions
        const e = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            e[i] = e1[i] ^ e2[i];
        }

        // We only need the least significant bit of byte 15
        const cipherBit = e[15] & 1;

        // Extract the current bit from the original IP
        const currentBitPos = 127 - prefixLenBits;

        // Set the bit in the encrypted result
        const originalBit = getBit(bytes16, currentBitPos);
        setBit(encrypted, currentBitPos, cipherBit ^ originalBit);

        // Prepare padded_prefix for next iteration
        // Shift left by 1 bit and insert the next bit from bytes16
        paddedPrefix = shiftLeftOneBit(paddedPrefix);
        setBit(paddedPrefix, 0, originalBit);
    }

    return bytesToIp(encrypted);
}

/**
 * Decrypt an IP address using ipcrypt-pfx.
 * @param {string} encryptedIp - Encrypted IP address string
 * @param {Uint8Array} key - 32-byte encryption key
 * @returns {string} Decrypted IP address string
 * @throws {Error} If key is invalid or halves are identical
 */
export function decrypt(encryptedIp, key) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be 32 bytes');
    }

    // Split the key into two AES-128 keys
    const K1 = key.slice(0, 16);
    const K2 = key.slice(16, 32);

    // Check that K1 and K2 are different
    if (K1.every((byte, i) => byte === K2[i])) {
        throw new Error('The two halves of the key must be different');
    }

    // Convert encrypted IP to 16-byte representation
    const encryptedBytes = ipToBytes(encryptedIp);

    // Initialize decrypted result with zeros
    const decrypted = new Uint8Array(16);

    // Determine starting point
    const ipv4 = isIPv4(encryptedBytes);
    const prefixStart = ipv4 ? 96 : 0;

    // If IPv4, copy the IPv4-mapped prefix
    if (ipv4) {
        decrypted.set(encryptedBytes.slice(0, 12), 0);
    }

    // No need to create cipher objects - we'll use aesEncrypt directly

    // Initialize padded_prefix for the starting prefix length
    let paddedPrefix;
    if (prefixStart === 0) {
        paddedPrefix = padPrefix0();
    } else {
        paddedPrefix = padPrefix96();
    }

    // Process each bit position
    for (let prefixLenBits = prefixStart; prefixLenBits < 128; prefixLenBits++) {
        // Compute pseudorandom function with dual AES encryption
        const e1 = aesEncrypt(K1, paddedPrefix);
        const e2 = aesEncrypt(K2, paddedPrefix);

        // XOR the two encryptions
        const e = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            e[i] = e1[i] ^ e2[i];
        }

        // We only need the least significant bit of byte 15
        const cipherBit = e[15] & 1;

        // Extract the current bit from the encrypted IP
        const currentBitPos = 127 - prefixLenBits;

        // Set the bit in the decrypted result
        const encryptedBit = getBit(encryptedBytes, currentBitPos);
        const originalBit = cipherBit ^ encryptedBit;
        setBit(decrypted, currentBitPos, originalBit);

        // Prepare padded_prefix for next iteration
        // Shift left by 1 bit and insert the next bit from decrypted
        paddedPrefix = shiftLeftOneBit(paddedPrefix);
        setBit(paddedPrefix, 0, originalBit);
    }

    return bytesToIp(decrypted);
}