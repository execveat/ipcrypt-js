import { subBytes, shiftRows, mixColumns, expandKey } from './aes.js';

/**
 * Pads an 8-byte tweak to 16 bytes according to KIASU-BC specification.
 * The tweak is padded by placing each 2-byte pair at the start of a 4-byte group,
 * effectively creating a sparse representation where every other byte is zero.
 * This padding scheme is specific to KIASU-BC and helps prevent certain cryptographic attacks.
 * 
 * Example:
 * Input tweak:  [t0,t1,t2,t3,t4,t5,t6,t7]
 * Padded tweak: [t0,t1,0,0,t2,t3,0,0,t4,t5,0,0,t6,t7,0,0]
 * 
 * @param {Uint8Array} tweak - 8-byte tweak
 * @returns {Uint8Array} 16-byte padded tweak
 * @throws {Error} If tweak is invalid
 */
function padTweak(tweak) {
    if (!(tweak instanceof Uint8Array) || tweak.length !== 8) {
        throw new Error('Tweak must be an 8-byte Uint8Array');
    }

    const padded = new Uint8Array(16);
    for (let i = 0; i < 8; i += 2) {
        padded[i * 2] = tweak[i];
        padded[i * 2 + 1] = tweak[i + 1];
    }
    return padded;
}

/**
 * Encrypts a 16-byte block using KIASU-BC with the given key and tweak.
 * 
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} tweak - 8-byte tweak
 * @param {Uint8Array} block - 16-byte block to encrypt
 * @returns {Uint8Array} 16-byte encrypted block
 * @throws {Error} If inputs are invalid
 */
export function encrypt(key, tweak, block) {
    // Validate inputs
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }
    if (!(tweak instanceof Uint8Array) || tweak.length !== 8) {
        throw new Error('Tweak must be an 8-byte Uint8Array');
    }
    if (!(block instanceof Uint8Array) || block.length !== 16) {
        throw new Error('Block must be a 16-byte Uint8Array');
    }

    // Pad tweak and expand key
    const paddedTweak = padTweak(tweak);
    const expandedKey = expandKey(key);
    const state = new Uint8Array(block);

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[i] ^ paddedTweak[i];
    }

    // Main rounds
    for (let round = 1; round < 10; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[round * 16 + i] ^ paddedTweak[i];
        }
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[160 + i] ^ paddedTweak[i];
    }

    return state;
}

/**
 * Decrypts a 16-byte block using KIASU-BC with the given key and tweak.
 * 
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} tweak - 8-byte tweak
 * @param {Uint8Array} block - 16-byte block to decrypt
 * @returns {Uint8Array} 16-byte decrypted block
 * @throws {Error} If inputs are invalid
 */
export function decrypt(key, tweak, block) {
    // Validate inputs
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }
    if (!(tweak instanceof Uint8Array) || tweak.length !== 8) {
        throw new Error('Tweak must be an 8-byte Uint8Array');
    }
    if (!(block instanceof Uint8Array) || block.length !== 16) {
        throw new Error('Block must be a 16-byte Uint8Array');
    }

    // Pad tweak and expand key
    const paddedTweak = padTweak(tweak);
    const expandedKey = expandKey(key);
    const state = new Uint8Array(block);

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[160 + i] ^ paddedTweak[i];
    }
    shiftRows(state, true);
    subBytes(state, true);

    // Main rounds
    for (let round = 9; round > 0; round--) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= expandedKey[round * 16 + i] ^ paddedTweak[i];
        }
        mixColumns(state, true);
        shiftRows(state, true);
        subBytes(state, true);
    }

    // Final round
    for (let i = 0; i < 16; i++) {
        state[i] ^= expandedKey[i] ^ paddedTweak[i];
    }

    return state;
}