"use strict";
/*
 * Copyright © 2022 Boris Bobylev. All rights reserved.
 * Licensed under the Apache License, Version 2.0
 *
 * V2Crypto — all VRack2 "v2" protocol cryptography, isolated from the transport.
 *
 * Built on the standard WebCrypto API (`crypto.subtle`) only, so the same code runs in a
 * browser (secure context: https / localhost) and in Node.js (>= 15) with no polyfills:
 *
 *   • key agreement   — ECDH P-256
 *   • channel key     — HKDF-SHA256 (32 bytes)
 *   • frames          — AES-256-GCM, base64url(nonce ‖ ciphertext ‖ tag)
 *
 * Every frame is authenticated against AAD `{ c: clientId, s: seq, d: req|res, v: session }`,
 * which binds it to one session, one direction and one sequence number (replay / transfer guard).
 * The HKDF salt/info strings and the AAD shape MUST match the server byte-for-byte.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.V2Crypto = void 0;
const enc = new TextEncoder();
const dec = new TextDecoder();
/** base64url (RFC 4648 §5) encode, no padding. */
function b64urlEncode(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++)
        bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
/** Decode base64url (also plain base64 — `-`/`_` are no-ops there) into bytes. */
function b64Decode(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (str.length % 4)) % 4);
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
/** Strip PEM headers / whitespace, leaving the base64 body. */
function pemBody(pem) {
    return pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}
const CURVE = { name: 'ECDH', namedCurve: 'P-256' };
const GCM = { name: 'AES-GCM', tagLength: 128 };
class V2Crypto {
    /** Pass a `SubtleCrypto` to inject a fake for tests; defaults to the global WebCrypto. */
    constructor(subtle) {
        const s = subtle !== null && subtle !== void 0 ? subtle : (typeof crypto !== 'undefined' ? crypto.subtle : undefined);
        if (!s)
            throw new Error('WebCrypto (crypto.subtle) is required — use a secure context (https/localhost) or Node.js >= 15');
        this.subtle = s;
    }
    /* ------------------------- key import & derivation ------------------------- */
    /** Import an ECDH P-256 private key from PEM (PKCS#8). */
    importEcdhPrivateKey(pem) {
        return this.subtle.importKey('pkcs8', b64Decode(pemBody(pem)), CURVE, false, ['deriveBits']);
    }
    /** Import a peer ECDH P-256 public key from PEM(SPKI) or base64url(SPKI). */
    importEcdhPublicKey(serverPub) {
        return this.subtle.importKey('spki', b64Decode(pemBody(serverPub)), CURVE, false, []);
    }
    /** ECDH shared secret (32 bytes) from a private key and a peer public key. */
    deriveShared(privateKey, publicKey) {
        return this.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256).then((b) => new Uint8Array(b));
    }
    /** HKDF-SHA256 key expansion to 32 bytes. */
    hkdf(ikm, salt, info) {
        return this.subtle
            .importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits'])
            .then((ikmKey) => this.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) }, ikmKey, 256))
            .then((b) => new Uint8Array(b));
    }
    /** Wrap a 32-byte key into an AES-256-GCM key. */
    aesGcmKey(ikm) {
        return this.subtle.importKey('raw', ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }
    /* ------------------------- VRack2 v2 channel-key derivation ------------------------- */
    /** `ecdh` mode: `ek = HKDF(ikm=ECDH(priv, serverPub), salt=∅, info="vrack2/v2/ek")`. */
    deriveEcdhChannelKey(clientPrivPem, serverPub) {
        return (() => __awaiter(this, void 0, void 0, function* () {
            const [priv, pub] = yield Promise.all([this.importEcdhPrivateKey(clientPrivPem), this.importEcdhPublicKey(serverPub)]);
            const ikm = yield this.hkdf(yield this.deriveShared(priv, pub), new Uint8Array(0), 'vrack2/v2/ek');
            return this.aesGcmKey(ikm);
        }))();
    }
    /** `legacy` mode: `ek = HKDF(ikm=secret, salt="vrack2/v2", info="vrack2/v2/ek")`. */
    deriveLegacyChannelKey(secret) {
        return this.hkdf(enc.encode(secret), enc.encode('vrack2/v2'), 'vrack2/v2/ek').then((ikm) => this.aesGcmKey(ikm));
    }
    /* ------------------------- framed (de)encryption ------------------------- */
    /** Encrypt a payload into a frame: `base64url(12-byte nonce ‖ ciphertext ‖ 16-byte tag)`. */
    frameEncrypt(ek, payload, clientId, seq, dir, session) {
        const nonce = new Uint8Array(12);
        crypto.getRandomValues(nonce);
        return this.subtle.encrypt(Object.assign(Object.assign({}, GCM), { iv: nonce, additionalData: V2Crypto.aad(clientId, seq, dir, session) }), ek, enc.encode(payload))
            .then((ct) => {
            const cipher = new Uint8Array(ct);
            const out = new Uint8Array(nonce.length + cipher.length);
            out.set(nonce, 0);
            out.set(cipher, 12);
            return b64urlEncode(out);
        });
    }
    /** Decrypt a frame back into a payload. Throws on a bad tag / AAD / seq / key. */
    frameDecrypt(ek, frame, clientId, seq, dir, session) {
        const raw = b64Decode(frame);
        if (raw.length < 28)
            throw new Error('Frame too short');
        return this.subtle.decrypt(Object.assign(Object.assign({}, GCM), { iv: raw.subarray(0, 12), additionalData: V2Crypto.aad(clientId, seq, dir, session) }), ek, raw.subarray(12))
            .then((b) => dec.decode(new Uint8Array(b)));
    }
    /** AAD binding a frame to one session / direction / sequence. Must match the server exactly. */
    static aad(clientId, seq, dir, session) {
        return enc.encode(JSON.stringify({ c: clientId, s: seq, d: dir, v: session }));
    }
}
exports.V2Crypto = V2Crypto;
