import * as det from './src/ipcrypt-deterministic.js';
import * as nd from './src/ipcrypt-nd.js';
import { encrypt as encryptNdx, decrypt as decryptNdx } from './src/ipcrypt-ndx.js';
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

export const utils = {
    ipToBytes,
    bytesToIp
}; 