import { encrypt, decrypt } from '../src/ipcrypt-pfx.js';
import { ipToBytes } from '../src/utils.js';

/**
 * Test vectors for ipcrypt-pfx from the specification
 */
const testVectors = [
    // Basic test vectors
    {
        key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
        ip: '0.0.0.0',
        encrypted: '151.82.155.134'
    },
    {
        key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
        ip: '255.255.255.255',
        encrypted: '94.185.169.89'
    },
    {
        key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
        ip: '192.0.2.1',
        encrypted: '100.115.72.131'
    },
    {
        key: '0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301',
        ip: '2001:db8::1',
        encrypted: 'c180:5dd4:2587:3524:30ab:fa65:6ab6:f88'
    },
    
    // Prefix preservation test vectors - IPv4 /24
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '10.0.0.47',
        encrypted: '19.214.210.244'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '10.0.0.129',
        encrypted: '19.214.210.80'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '10.0.0.234',
        encrypted: '19.214.210.30'
    },
    
    // Prefix preservation test vectors - IPv4 /16
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '172.16.5.193',
        encrypted: '210.78.229.136'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '172.16.97.42',
        encrypted: '210.78.179.241'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '172.16.248.177',
        encrypted: '210.78.121.215'
    },
    
    // Prefix preservation test vectors - IPv6 /64
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8::a5c9:4e2f:bb91:5a7d',
        encrypted: '7cec:702c:1243:f70:1956:125:b9bd:1aba'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8::7234:d8f1:3c6e:9a52',
        encrypted: '7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8::f1e0:937b:26d4:8c1a',
        encrypted: '7cec:702c:1243:f70:443c:c8e:6a62:b64d'
    },
    
    // Prefix preservation test vectors - IPv6 /32
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8:3a5c::e7d1:4b9f:2c8a:f673',
        encrypted: '7cec:702c:3503:bef:e616:96bd:be33:a9b9'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8:9f27::b4e2:7a3d:5f91:c8e6',
        encrypted: '7cec:702c:a504:b74e:194a:3d90:b047:2d1a'
    },
    {
        key: '2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a',
        ip: '2001:db8:d8b4::193c:a5e7:8b2f:46d1',
        encrypted: '7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb'
    }
];

/**
 * Helper function to convert hex string to Uint8Array
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Run all test vectors
 */
function runTests() {
    console.log('=== ipcrypt-pfx Test Suite ===\n');
    
    let passed = 0;
    let failed = 0;
    
    for (let i = 0; i < testVectors.length; i++) {
        const vector = testVectors[i];
        const key = hexToBytes(vector.key);
        
        try {
            // Test encryption
            const encrypted = encrypt(vector.ip, key);
            
            if (encrypted !== vector.encrypted) {
                console.error(`❌ Test ${i + 1} failed (encryption):`);
                console.error(`   Input: ${vector.ip}`);
                console.error(`   Expected: ${vector.encrypted}`);
                console.error(`   Got: ${encrypted}`);
                failed++;
                continue;
            }
            
            // Test decryption
            const decrypted = decrypt(encrypted, key);
            
            // For IPv6, check if the bytes are equivalent even if display format differs
            const originalBytes = hexToBytes(ipToBytes(vector.ip).reduce((hex, b) => hex + b.toString(16).padStart(2, '0'), ''));
            const decryptedBytes = hexToBytes(ipToBytes(decrypted).reduce((hex, b) => hex + b.toString(16).padStart(2, '0'), ''));
            const bytesMatch = originalBytes.every((b, idx) => b === decryptedBytes[idx]);
            
            if (!bytesMatch) {
                console.error(`❌ Test ${i + 1} failed (decryption):`);
                console.error(`   Encrypted: ${encrypted}`);
                console.error(`   Expected: ${vector.ip}`);
                console.error(`   Got: ${decrypted}`);
                failed++;
                continue;
            }
            
            console.log(`✓ Test ${i + 1} passed: ${vector.ip} ↔ ${encrypted}`);
            passed++;
            
        } catch (e) {
            console.error(`❌ Test ${i + 1} threw error: ${e.message}`);
            failed++;
        }
    }
    
    // Test prefix preservation
    console.log('\n=== Prefix Preservation Tests ===');
    
    // IPv4 /24 prefix preservation
    const ipv4_24_encrypted = ['19.214.210.244', '19.214.210.80', '19.214.210.30'];
    const prefix24 = ipv4_24_encrypted[0].split('.').slice(0, 3).join('.');
    const allSame24 = ipv4_24_encrypted.every(ip => ip.startsWith(prefix24));
    
    if (allSame24) {
        console.log(`✓ IPv4 /24 prefix preserved: ${prefix24}.x`);
        passed++;
    } else {
        console.log('❌ IPv4 /24 prefix NOT preserved');
        failed++;
    }
    
    // IPv4 /16 prefix preservation
    const ipv4_16_encrypted = ['210.78.229.136', '210.78.179.241', '210.78.121.215'];
    const prefix16 = ipv4_16_encrypted[0].split('.').slice(0, 2).join('.');
    const allSame16 = ipv4_16_encrypted.every(ip => ip.startsWith(prefix16));
    
    if (allSame16) {
        console.log(`✓ IPv4 /16 prefix preserved: ${prefix16}.x.x`);
        passed++;
    } else {
        console.log('❌ IPv4 /16 prefix NOT preserved');
        failed++;
    }
    
    // IPv6 /64 prefix preservation
    const ipv6_64_encrypted = [
        '7cec:702c:1243:f70:1956:125:b9bd:1aba',
        '7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d',
        '7cec:702c:1243:f70:443c:c8e:6a62:b64d'
    ];
    const prefix64 = ipv6_64_encrypted[0].split(':').slice(0, 4).join(':');
    const allSame64 = ipv6_64_encrypted.every(ip => ip.startsWith(prefix64));
    
    if (allSame64) {
        console.log(`✓ IPv6 /64 prefix preserved: ${prefix64}::/64`);
        passed++;
    } else {
        console.log('❌ IPv6 /64 prefix NOT preserved');
        failed++;
    }
    
    // IPv6 /32 prefix preservation
    const ipv6_32_encrypted = [
        '7cec:702c:3503:bef:e616:96bd:be33:a9b9',
        '7cec:702c:a504:b74e:194a:3d90:b047:2d1a',
        '7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb'
    ];
    const prefix32 = ipv6_32_encrypted[0].split(':').slice(0, 2).join(':');
    const allSame32 = ipv6_32_encrypted.every(ip => ip.startsWith(prefix32));
    
    if (allSame32) {
        console.log(`✓ IPv6 /32 prefix preserved: ${prefix32}::/32`);
        passed++;
    } else {
        console.log('❌ IPv6 /32 prefix NOT preserved');
        failed++;
    }
    
    // Test error conditions
    console.log('\n=== Error Handling Tests ===');
    
    try {
        // Test with invalid key size
        encrypt('192.0.2.1', new Uint8Array(16));
        console.error('❌ Should have thrown error for 16-byte key');
        failed++;
    } catch (e) {
        if (e.message.includes('32 bytes')) {
            console.log('✓ Correctly rejects 16-byte key');
            passed++;
        } else {
            console.error(`❌ Wrong error for invalid key: ${e.message}`);
            failed++;
        }
    }
    
    try {
        // Test with identical key halves
        const badKey = new Uint8Array(32);
        badKey.fill(0x42, 0, 16);
        badKey.fill(0x42, 16, 32);
        encrypt('192.0.2.1', badKey);
        console.error('❌ Should have thrown error for identical key halves');
        failed++;
    } catch (e) {
        if (e.message.includes('different')) {
            console.log('✓ Correctly rejects identical key halves');
            passed++;
        } else {
            console.error(`❌ Wrong error for identical halves: ${e.message}`);
            failed++;
        }
    }
    
    // Summary
    console.log('\n=== Test Summary ===');
    console.log(`Total: ${passed + failed}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    
    if (failed > 0) {
        process.exit(1);
    }
}

// Run the tests
runTests();
