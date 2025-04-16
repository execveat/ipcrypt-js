import { ipToBytes, bytesToIp } from '../src/utils.js';

// Function to generate random IPv4 address
function generateRandomIPv4() {
    return Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
}

// Function to generate random IPv6 address
function generateRandomIPv6() {
    return Array.from({ length: 8 }, () =>
        Math.floor(Math.random() * 65536)
            .toString(16)
            .padStart(4, '0')
    ).join(':');
}

// Test IPv4 addresses
const ipv4Tests = [
    '0.0.0.0',
    '192.0.2.1',
    '255.255.255.255'
];

// Test IPv6 addresses
const ipv6Tests = [
    '2001:db8:85a3:0:0:8a2e:370:7334',
    '2001:DB8:85A3:0:0:8A2E:370:7334',  // Uppercase version
    '2001:db8::1',
    '2001:DB8::1',                      // Uppercase version
    'fe80::1',
    'FE80::1',                          // Uppercase version
    '::1',
    '::'
];

console.log('Testing IPv4 addresses:');
for (const ip of ipv4Tests) {
    try {
        const bytes = ipToBytes(ip);
        const roundTrip = bytesToIp(bytes);
        console.log(`${ip} -> ${roundTrip} (${roundTrip === ip ? 'OK' : 'FAIL'})`);
    } catch (e) {
        console.error(`Error with ${ip}:`, e.message);
    }
}

console.log('\nTesting IPv6 addresses:');
for (const ip of ipv6Tests) {
    try {
        const bytes = ipToBytes(ip);
        const roundTrip = bytesToIp(bytes);
        console.log(`${ip} -> ${roundTrip}`);
    // Note: IPv6 addresses might not match exactly due to different representations
    // but they should represent the same address
    } catch (e) {
        console.error(`Error with ${ip}:`, e.message);
    }
}

// Test invalid addresses
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
        ipToBytes(ip);
        console.error(`Should have failed: ${ip}`);
    } catch (e) {
        console.log(`${ip} -> ${e.message} (OK)`);
    }
}

// Test random IP addresses
console.log('\nTesting 1000 random IPv4 addresses:');
let ipv4Success = 0;
for (let i = 0; i < 1000; i++) {
    const ip = generateRandomIPv4();
    try {
        const bytes = ipToBytes(ip);
        const roundTrip = bytesToIp(bytes);
        if (roundTrip === ip) {
            ipv4Success++;
        } else {
            console.error(`IPv4 mismatch: ${ip} -> ${roundTrip}`);
        }
    } catch (e) {
        console.error(`Error with random IPv4 ${ip}:`, e.message);
    }
}
console.log(`IPv4 Success rate: ${(ipv4Success / 1000 * 100).toFixed(2)}%`);

console.log('\nTesting 1000 random IPv6 addresses:');
let ipv6Success = 0;
for (let i = 0; i < 1000; i++) {
    const ip = generateRandomIPv6();
    try {
        const bytes = ipToBytes(ip);
        const roundTrip = bytesToIp(bytes);
        // For IPv6, we need to normalize the addresses before comparison
        const normalizedInput = ipToBytes(ip);
        const normalizedOutput = ipToBytes(roundTrip);
        if (normalizedInput.every((byte, index) => byte === normalizedOutput[index])) {
            ipv6Success++;
        } else {
            console.error(`IPv6 mismatch: ${ip} -> ${roundTrip}`);
        }
    } catch (e) {
        console.error(`Error with random IPv6 ${ip}:`, e.message);
    }
}
console.log(`IPv6 Success rate: ${(ipv6Success / 1000 * 100).toFixed(2)}%`); 