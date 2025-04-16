import { ipToBytes, bytesToIp } from './utils.js';
import { expandKey, subBytes, shiftRows, mixColumns } from './core/aes.js';

/**
 * Encrypts an IP address using AES-128 in a deterministic mode.
 * This mode ensures that the same input IP address and key will always produce
 * the same output, making it suitable for scenarios where consistent mapping
 * is required (e.g., database lookups, load balancing).
 * 
 * The encryption process:
 * 1. Convert IP address to a 16-byte block
 * 2. Apply standard AES-128 encryption
 * 3. Convert result back to IP address format
 * 
 * Security note: Because this mode is deterministic, it may leak information
 * about IP address patterns. Use non-deterministic modes for higher security.
 * 
 * @param {string} ip - IP address to encrypt (IPv4 or IPv6)
 * @param {Uint8Array} key - 16-byte encryption key
 * @returns {string} Encrypted IP address
 * @throws {Error} If inputs are invalid
 */
export function encrypt(ip, key) {
    // Validate key
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }

    // Convert IP to bytes
    const state = ipToBytes(ip);

    // Expand key
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

    // Convert back to IP address
    return bytesToIp(state);
}

/**
 * Decrypts an IP address that was encrypted using AES-128 deterministic mode.
 * The decryption process is the inverse of encryption:
 * 1. Convert encrypted IP address to a 16-byte block
 * 2. Apply standard AES-128 decryption
 * 3. Convert result back to IP address format
 * 
 * @param {string} encryptedIp - Encrypted IP address
 * @param {Uint8Array} key - 16-byte encryption key (must be same as encryption)
 * @returns {string} Decrypted IP address
 * @throws {Error} If inputs are invalid
 */
export function decrypt(encryptedIp, key) {
    // Validate key
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }

    // Convert IP to bytes
    const state = ipToBytes(encryptedIp);

    // Expand key
    const expandedKey = expandKey(key);

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[160 + i];
    }
    shiftRows(state, true);
    subBytes(state, true);

    // Main rounds
    for (let round = 9; round > 0; round--) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[round * 16 + i];
        }
        mixColumns(state, true);
        shiftRows(state, true);
        subBytes(state, true);
    }

    // Final round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[i];
    }

    // Convert back to IP address
    return bytesToIp(state);
} 