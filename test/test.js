import * as det from '../src/ipcrypt-deterministic.js';
import * as nd from '../src/ipcrypt-nd.js';
import { encrypt as encryptNdx, decrypt as decryptNdx } from '../src/ipcrypt-ndx.js';
import { ipToBytes, bytesToIp } from '../src/utils.js';

// Helper function to convert hex string to Uint8Array
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

// Helper function to convert Uint8Array to hex string
function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

console.log('Running ipcrypt test vectors...\n');

// Test vectors from the draft specification
console.log('\nTesting ipcrypt-deterministic...');
const detTestVectors = [
    {
        key: '0123456789abcdeffedcba9876543210',
        input: '0.0.0.0',
        expected: 'bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb'
    },
    {
        key: '1032547698badcfeefcdab8967452301',
        input: '255.255.255.255',
        expected: 'aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3c',
        input: '192.0.2.1',
        expected: '1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777'
    }
];

for (const [i, test] of detTestVectors.entries()) {
    console.log(`\nTest vector ${i + 1}:`);
    const key = hexToBytes(test.key);
    const encrypted = det.encrypt(test.input, key);
    console.log(`Input: ${test.input}`);
    console.log(`Expected: ${test.expected}`);
    console.log(`Got: ${encrypted}`);
    if (encrypted === test.expected) {
        console.log('✅ Encryption passed');
        const decrypted = det.decrypt(encrypted, key);
        if (decrypted === test.input) {
            console.log('✅ Decryption passed');
        } else {
            console.log(`❌ Decryption failed. Expected ${test.input}, got ${decrypted}`);
        }
    } else {
        console.log('❌ Encryption failed');
    }
}

// Test vectors for ipcrypt-nd
console.log('\nTesting ipcrypt-nd...');
const ndTestVectors = [
    {
        key: '0123456789abcdeffedcba9876543210',
        input: '0.0.0.0',
        tweak: '08e0c289bff23b7c',
        expected: '08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16'
    },
    {
        key: '1032547698badcfeefcdab8967452301',
        input: '192.0.2.1',
        tweak: '21bd1834bc088cd2',
        expected: '21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3c',
        input: '2001:db8::1',
        tweak: 'b4ecbe30b70898d7',
        expected: 'b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96'
    }
];

for (const [i, test] of ndTestVectors.entries()) {
    console.log(`\nTest vector ${i + 1}:`);
    const key = hexToBytes(test.key);
    const tweak = hexToBytes(test.tweak);
    const encrypted = nd.encrypt(test.input, key, tweak);
    const encryptedHex = bytesToHex(encrypted);
    console.log(`Input: ${test.input}`);
    console.log(`Expected: ${test.expected}`);
    console.log(`Got: ${encryptedHex}`);
    if (encryptedHex === test.expected) {
        console.log('✅ Encryption passed');
        const decrypted = nd.decrypt(encrypted, key);
        if (decrypted === test.input) {
            console.log('✅ Decryption passed');
        } else {
            console.log(`❌ Decryption failed. Expected ${test.input}, got ${decrypted}`);
        }
    } else {
        console.log('❌ Encryption failed');
    }
}

// Test vectors for ipcrypt-ndx
console.log('\nTesting ipcrypt-ndx...');
const ndxTestVectors = [
    {
        key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
        input: '0.0.0.0',
        tweak: '21bd1834bc088cd2b4ecbe30b70898d7',
        expected: '21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5'
    },
    {
        key: '1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210',
        input: '192.0.2.1',
        tweak: '08e0c289bff23b7cb4ecbe30b70898d7',
        expected: '08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b',
        input: '2001:db8::1',
        tweak: '21bd1834bc088cd2b4ecbe30b70898d7',
        expected: '21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4'
    }
];

for (const [i, test] of ndxTestVectors.entries()) {
    console.log(`\nTest vector ${i + 1}:`);
    const key = hexToBytes(test.key);
    const tweak = hexToBytes(test.tweak);
    const encrypted = encryptNdx(test.input, key, tweak);
    const encryptedHex = bytesToHex(encrypted);
    console.log(`Input: ${test.input}`);
    console.log(`Expected: ${test.expected}`);
    console.log(`Got: ${encryptedHex}`);
    if (encryptedHex === test.expected) {
        console.log('✅ Encryption passed');
        const decrypted = decryptNdx(encrypted, key);
        if (decrypted === test.input) {
            console.log('✅ Decryption passed');
        } else {
            console.log(`❌ Decryption failed. Expected ${test.input}, got ${decrypted}`);
        }
    } else {
        console.log('❌ Encryption failed');
    }
}

// Test IP address handling
console.log('Testing IPv4 addresses:');
const ipv4Tests = ['0.0.0.0', '192.0.2.1', '255.255.255.255'];
for (const ip of ipv4Tests) {
    const roundTrip = bytesToIp(ipToBytes(ip));
    console.log(`${ip} -> ${roundTrip} ${roundTrip === ip ? '(OK)' : '(FAIL)'}`);
}

console.log('\nTesting IPv6 addresses:');
const ipv6Tests = [
    '2001:db8:85a3:0:0:8a2e:370:7334',
    '2001:db8::1',
    'fe80::1',
    '::1',
    '::'
];
for (const ip of ipv6Tests) {
    const roundTrip = bytesToIp(ipToBytes(ip));
    console.log(`${ip} -> ${roundTrip}`);
}

console.log('\nTesting invalid addresses:');
const invalidTests = [
    '256.256.256.256',  // Invalid IPv4
    '1.2.3.4.5',        // Too many octets
    '1.2.3',            // Too few octets
    '2001:db8::g',      // Invalid hex
    '2001:db8:::1',     // Invalid :: usage
    null,               // Not a string
    '',                // Empty string
    '   ',             // Whitespace
];

for (const ip of invalidTests) {
    try {
        bytesToIp(ipToBytes(ip));
        console.error(`Should have failed: ${ip}`);
    } catch (e) {
        console.log(`${ip} -> ${e.message} (OK)`);
    }
}

// Test error cases
console.log('\nTesting error cases...');
try {
    det.encrypt('invalid', new Uint8Array(15));
    console.log('Failed: Should throw error for invalid key length');
} catch (e) {
    console.log('Passed: ' + e.message);
}

try {
    nd.encrypt('192.168.1.1', new Uint8Array(16), new Uint8Array(7));
    console.log('Failed: Should throw error for invalid tweak length');
} catch (e) {
    console.log('Passed: ' + e.message);
}

try {
    nd.decrypt(new Uint8Array(23), new Uint8Array(16));
    console.log('Failed: Should throw error for invalid input length');
} catch (e) {
    console.log('Passed: ' + e.message);
} 