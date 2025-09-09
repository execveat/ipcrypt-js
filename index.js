import * as det from './src/ipcrypt-deterministic.js';
import * as nd from './src/ipcrypt-nd.js';
import { encrypt as encryptNdx, decrypt as decryptNdx } from './src/ipcrypt-ndx.js';
import { encrypt as encryptPfx, decrypt as decryptPfx } from './src/ipcrypt-pfx.js';
import { ipToBytes, bytesToIp } from './src/utils.js';

export const deterministic = {
    encrypt: det.encrypt,
    decrypt: det.decrypt
};

export const nonDeterministic = {
    encrypt: nd.encrypt,
    decrypt: nd.decrypt
};

export const nonDeterministicExtended = {
    encrypt: encryptNdx,
    decrypt: decryptNdx
};

export const prefixPreserving = {
    encrypt: encryptPfx,
    decrypt: decryptPfx
};

export const utils = {
    ipToBytes,
    bytesToIp
}; 