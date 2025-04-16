# IPCrypt - JS

A JavaScript implementation of the IP address encryption and obfuscation methods specified in the [ipcrypt document](https://datatracker.ietf.org/doc/draft-denis-ipcrypt/) ("Methods for IP Address Encryption and Obfuscation").

## Installation

```sh
# Using npm (Node.js)
npm install ipcrypt

# Using Bun
bun add ipcrypt
```

## Overview

IPCrypt provides three different methods for IP address encryption:

1. **Deterministic Encryption**: Uses AES-128 in a deterministic mode, where the same input always produces the same output for a given key. This is useful when you need to consistently map IP addresses to encrypted values.

2. **Non-Deterministic Encryption**: Uses KIASU-BC, a tweakable block cipher, to provide non-deterministic encryption. This means the same input can produce different outputs, providing better privacy protection.

3. **Extended Non-Deterministic Encryption**: An enhanced version of non-deterministic encryption that uses a larger key and tweak size for increased security.

## Usage

### Deterministic Encryption

```javascript
import { deterministic } from 'ipcrypt';

// Create a 16-byte key
const key = new Uint8Array(16);
crypto.getRandomValues(key);

// Encrypt an IP address
const encrypted = deterministic.encrypt('192.168.1.1', key);
console.log(encrypted); // Encrypted IP address

// Decrypt the IP address
const decrypted = deterministic.decrypt(encrypted, key);
console.log(decrypted); // '192.168.1.1'
```

### Non-Deterministic Encryption

```javascript
import { nonDeterministic } from 'ipcrypt';

// Create a 16-byte key and 8-byte tweak
const key = new Uint8Array(16);
const tweak = new Uint8Array(8);
crypto.getRandomValues(key);
crypto.getRandomValues(tweak);

// Encrypt an IP address
const encrypted = nonDeterministic.encrypt('192.168.1.1', key, tweak);
console.log(encrypted); // Uint8Array containing encrypted data

// Decrypt the IP address
const decrypted = nonDeterministic.decrypt(encrypted, key);
console.log(decrypted); // '192.168.1.1'
```

### Extended Non-Deterministic Encryption

```javascript
import { nonDeterministicExtended } from 'ipcrypt';

// Create a 32-byte key and 16-byte tweak
const key = new Uint8Array(32);
const tweak = new Uint8Array(16);
crypto.getRandomValues(key);
crypto.getRandomValues(tweak);

// Encrypt an IP address
const encrypted = nonDeterministicExtended.encrypt('192.168.1.1', key, tweak);
console.log(encrypted); // Uint8Array containing encrypted data

// Decrypt the IP address
const decrypted = nonDeterministicExtended.decrypt(encrypted, key);
console.log(decrypted); // '192.168.1.1'
```

### Utility Functions

```javascript
import { utils } from 'ipcrypt';

// Convert IP address to bytes
const bytes = utils.ipToBytes('192.168.1.1');
console.log(bytes); // Uint8Array

// Convert bytes back to IP address
const ip = utils.bytesToIp(bytes);
console.log(ip); // '192.168.1.1'
```

## API Reference

### Deterministic Encryption

- `deterministic.encrypt(ip: string, key: Uint8Array): string`
  - Encrypts an IP address using AES-128 in deterministic mode
  - `ip`: IPv4 or IPv6 address to encrypt
  - `key`: 16-byte encryption key
  - Returns: Encrypted IP address as a string

- `deterministic.decrypt(encrypted: string, key: Uint8Array): string`
  - Decrypts an encrypted IP address
  - `encrypted`: Encrypted IP address
  - `key`: 16-byte encryption key
  - Returns: Original IP address

### Non-Deterministic Encryption

- `nonDeterministic.encrypt(ip: string, key: Uint8Array, tweak: Uint8Array): Uint8Array`
  - Encrypts an IP address using KIASU-BC
  - `ip`: IPv4 or IPv6 address to encrypt
  - `key`: 16-byte encryption key
  - `tweak`: 8-byte tweak value
  - Returns: Encrypted data as Uint8Array

- `nonDeterministic.decrypt(encrypted: Uint8Array, key: Uint8Array): string`
  - Decrypts an encrypted IP address
  - `encrypted`: Encrypted data
  - `key`: 16-byte encryption key
  - Returns: Original IP address

### Extended Non-Deterministic Encryption

- `nonDeterministicExtended.encrypt(ip: string, key: Uint8Array, tweak: Uint8Array): Uint8Array`
  - Encrypts an IP address using extended KIASU-BC
  - `ip`: IPv4 or IPv6 address to encrypt
  - `key`: 32-byte encryption key
  - `tweak`: 16-byte tweak value
  - Returns: Encrypted data as Uint8Array

- `nonDeterministicExtended.decrypt(encrypted: Uint8Array, key: Uint8Array): string`
  - Decrypts an encrypted IP address
  - `encrypted`: Encrypted data
  - `key`: 32-byte encryption key
  - Returns: Original IP address

### Utilities

- `utils.ipToBytes(ip: string): Uint8Array`
  - Converts an IP address to bytes
  - `ip`: IPv4 or IPv6 address
  - Returns: IP address as bytes

- `utils.bytesToIp(bytes: Uint8Array): string`
  - Converts bytes back to an IP address
  - `bytes`: IP address bytes
  - Returns: IP address as string

## License

ISC License
