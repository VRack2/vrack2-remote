"use strict";
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
const events_1 = require("events");
/* ----------------------------- WebCrypto backend ----------------------------- */
function subtle() {
    const c = globalThis.crypto;
    if (!c || !c.subtle)
        throw new Error('crypto.subtle is unavailable — use a secure context (https / localhost) in the browser, or Node.js >= 15');
    return c.subtle;
}
function randomBytes(n) {
    const c = globalThis.crypto;
    if (!c || typeof c.getRandomValues !== 'function')
        throw new Error('crypto.getRandomValues is unavailable — use Node.js >= 15 or a modern browser');
    const buf = new Uint8Array(n);
    c.getRandomValues(buf);
    return buf;
}
/** base64url (RFC 4648, no padding) encode. */
function b64urlEncode(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++)
        bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
/** base64url decode. */
function b64urlDecode(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0)
        s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
/** Strip PEM headers / whitespace -> raw DER ArrayBuffer. */
function pemToDer(pem) {
    const b64 = pem.replace(/-----(BEGIN|END)[A-Z0-9 ]+-----/g, '').replace(/\s+/g, '');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++)
        bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}
/** HKDF-SHA256 key expansion to `length` bytes. (WebCrypto needs the IKM imported as a CryptoKey.) */
function hkdf(ikm, salt, info, length) {
    return __awaiter(this, void 0, void 0, function* () {
        const ikmKey = yield subtle().importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
        const bits = yield subtle().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: new TextEncoder().encode(info) }, ikmKey, length * 8);
        return new Uint8Array(bits);
    });
}
/**
 * Asymmetric channel key: ECDH(clientPriv, serverPub) -> HKDF(salt=∅, info="vrack2/v2/ek").
 * Matches the server `Guard.deriveEK` (ECDH branch).
 */
function deriveEkEcdh(serverPubPem, clientPrivPem) {
    return __awaiter(this, void 0, void 0, function* () {
        const priv = yield subtle().importKey('pkcs8', pemToDer(clientPrivPem), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
        const pub = yield subtle().importKey('spki', pemToDer(serverPubPem), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const shared = new Uint8Array(yield subtle().deriveBits({ name: 'ECDH', public: pub }, priv, 256));
        return hkdf(shared, new Uint8Array(0), 'vrack2/v2/ek', 32);
    });
}
/**
 * Legacy shared-secret channel key: HKDF(ikm=secret, salt="vrack2/v2", info="vrack2/v2/ek").
 * Matches the server `Guard.deriveEK` (shared-secret branch).
 */
function deriveEkLegacy(secret) {
    return __awaiter(this, void 0, void 0, function* () {
        return hkdf(new TextEncoder().encode(secret), new TextEncoder().encode('vrack2/v2'), 'vrack2/v2/ek', 32);
    });
}
/** AAD binding the frame to session/channel/sequence/direction. Must match the server byte-for-byte. */
function buildAAD(clientId, seq, dir, session) {
    return new TextEncoder().encode(JSON.stringify({ c: clientId, s: seq, d: dir, v: session }));
}
/** Encrypt `payload` into a frame: base64url(nonce ‖ ciphertext ‖ tag), AES-256-GCM. */
function frameEncrypt(payload, ek, clientId, seq, dir, session) {
    return __awaiter(this, void 0, void 0, function* () {
        const key = yield subtle().importKey('raw', ek, { name: 'AES-GCM' }, false, ['encrypt']);
        const nonce = randomBytes(12);
        const ct = new Uint8Array(yield subtle().encrypt({ name: 'AES-GCM', iv: nonce, additionalData: buildAAD(clientId, seq, dir, session) }, key, new TextEncoder().encode(payload)));
        const out = new Uint8Array(12 + ct.length);
        out.set(nonce, 0);
        out.set(ct, 12);
        return b64urlEncode(out);
    });
}
/** Decrypt a frame back into `payload`. Throws on a bad tag / AAD / sequence / key. */
function frameDecrypt(frame, ek, clientId, seq, dir, session) {
    return __awaiter(this, void 0, void 0, function* () {
        const raw = b64urlDecode(frame);
        if (raw.length < 28)
            throw new Error('Frame too short');
        const nonce = raw.subarray(0, 12);
        const ct = raw.subarray(12); // ciphertext + 16-byte auth tag
        const key = yield subtle().importKey('raw', ek, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = new Uint8Array(yield subtle().decrypt({ name: 'AES-GCM', iv: nonce, additionalData: buildAAD(clientId, seq, dir, session) }, key, ct));
        return new TextDecoder().decode(pt);
    });
}
/* ----------------------------- Transport class ----------------------------- */
class VRackRemote extends events_1.EventEmitter {
    constructor(key = 'default', privateKey = '') {
        super();
        // Credentials
        this.key = 'default'; // KID (public key identifier)
        this.privateKey = ''; // PEM private key (ECDH) or shared secret (legacy)
        // Bookkeeping
        this.pkgIndex = 1000; // _pkgIndex counter (request/response correlation)
        this.channels = new Map();
        this.queue = new Map();
        this.queueTimeout = new Map();
        this.sendChain = Promise.resolve(); // serializes wire writes so frame order == seq order
        // Public state
        this.level = 1000; // access level (1/2/3/1000)
        this.timeout = 30000; // command timeout (ms)
        this.connected = false; // connection is up
        this.connection = false; // connection in progress
        this.cipher = false; // channel is encrypted (GCM frames)
        this.mode = null; // negotiated key mode
        this.commandsList = {};
        // Negotiated session state (set during apiKeyAuth)
        this.clientId = null; // server-assigned connection id (AAD `c`)
        this.session = null; // server challenge `verify` (AAD `v`)
        this.ek = null; // 32-byte channel key
        this.reqSeq = 1; // outbound (req) sequence, starts at 1
        this.resSeq = 1; // inbound  (res) sequence, starts at 1
        this.setKey(key);
        this.setPrivateKey(privateKey);
    }
    /**********  Key Management  ***************/
    /** Set the KID (public key identifier). */
    setKey(key = 'default') {
        this.key = key;
    }
    /** Set the private key: PEM (ECDH) or shared secret (legacy). Mode is auto-detected from the server answer. */
    setPrivateKey(privateKey = '') {
        this.privateKey = privateKey;
    }
    /**********  Transport Events  ***************/
    transportOnOpen() {
        this.connected = true;
        this.connection = false;
        this.emit('open');
    }
    transportOnClose() {
        this.connected = false;
        this.connection = false;
        this.cipher = false;
        this.level = 1000;
        this.mode = null;
        this.clientId = null;
        this.session = null;
        this.ek = null;
        this.reqSeq = 1;
        this.resSeq = 1;
        this.channels.clear();
        this.emit('close');
    }
    transportOnError(error) {
        this.emit('error', error);
    }
    /**
     * Handle an incoming message. If the channel is cipher-enabled the message is a GCM frame
     * (the raw base64url string); otherwise it is plain JSON (handshake or a plain key).
     */
    transportOnMessage(data) {
        return __awaiter(this, void 0, void 0, function* () {
            let text = data;
            if (this.cipher) {
                const seq = this.resSeq++;
                try {
                    text = yield frameDecrypt(data, this.ek, this.clientId, seq, 'res', this.session);
                }
                catch (error) {
                    // A failing auth tag means the channel is corrupted (replay / tamper / seq skew):
                    // surface it and stop trusting the connection.
                    this.transportOnError(error instanceof Error ? error : new Error('Frame decrypt failed'));
                    return;
                }
            }
            let remoteData;
            try {
                remoteData = JSON.parse(text);
            }
            catch (error) {
                this.transportOnError(error instanceof Error ? error : new Error('Invalid JSON from server'));
                return;
            }
            if (remoteData._pkgIndex != null && this.queue.has(remoteData._pkgIndex)) {
                const func = this.queue.get(remoteData._pkgIndex);
                const timer = this.queueTimeout.get(remoteData._pkgIndex);
                if (timer)
                    clearTimeout(timer);
                this.queue.delete(remoteData._pkgIndex);
                this.queueTimeout.delete(remoteData._pkgIndex);
                if (remoteData.result === 'error')
                    func.reject(this.errorify(remoteData.resultData));
                else
                    func.resolve(remoteData);
            }
            else if (remoteData.command === 'broadcast') {
                const cb = this.channels.get(remoteData.target);
                if (cb)
                    cb(remoteData);
            }
        });
    }
    /**********  Transport Methods (To be overridden)  ***************/
    transportSend(data) {
        // Implemented by a concrete transport (e.g. VRackRemoteWeb over WebSocket).
    }
    transportDisconnect() {
        // Implemented by a concrete transport.
    }
    /**********  Channel Methods  ***************/
    /** Join a broadcast channel. */
    channelJoin(channel, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = this.command('channelJoin', { channel });
            this.channels.set(channel, cb);
            return result;
        });
    }
    /** Leave a broadcast channel. */
    channelLeave(channel) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.command('channelLeave', { channel });
            this.channels.delete(channel);
            return result;
        });
    }
    /**********  Authentication Methods  ***************/
    /**
     * Authenticate. Sends `apiKeyAuth`; if the key requires a cipher channel it performs the
     * `apiPrivateAuth` proof (encrypts the server challenge as the first req frame) and derives
     * the channel key. After a successful proof the channel is encrypted.
     */
    apiKeyAuth() {
        return __awaiter(this, void 0, void 0, function* () {
            const auth = yield this.send('apiKeyAuth', { key: this.key });
            const rd = (auth.resultData || {});
            this.clientId = auth.clientId != null ? auth.clientId : null;
            this.session = null;
            this.ek = null;
            this.reqSeq = 1;
            this.resSeq = 1;
            if (!rd.verify) {
                // Plain key — the channel is already usable, no cipher.
                this.mode = 'plain';
                this.cipher = false;
                this.level = rd.level;
                return rd;
            }
            // Cipher key — need the secret to derive the channel key.
            if (!this.privateKey)
                throw new Error('This key requires encryption (verify), but no private key was set (setPrivateKey)');
            this.session = rd.verify;
            if (rd.serverPub) {
                this.mode = 'ecdh';
                this.ek = yield deriveEkEcdh(rd.serverPub, this.privateKey);
            }
            else {
                this.mode = 'legacy';
                this.ek = yield deriveEkLegacy(this.privateKey);
            }
            // Proof: encrypt the server challenge as the first outbound frame (req seq = 1).
            // The apiPrivateAuth request and its answer are plain JSON; only after this do we frame.
            const frame = yield frameEncrypt(rd.verify, this.ek, this.clientId, 1, 'req', rd.verify);
            const proof = yield this.send('apiPrivateAuth', { frame });
            this.cipher = true;
            this.level = proof.resultData ? proof.resultData.level : this.level;
            this.reqSeq = 2; // proof consumed req seq 1; next command is 2
            this.resSeq = 1; // the proof answer is plain, so the first framed answer is res seq 1
            return proof.resultData;
        });
    }
    /** Update the available-commands list from the server. */
    commandsListUpdate() {
        return __awaiter(this, void 0, void 0, function* () {
            const list = yield this.command('commandsList', {});
            if (Array.isArray(list)) {
                const obj = {};
                for (const item of list) {
                    if (item && item.command)
                        obj[item.command] = item;
                }
                this.commandsList = obj;
            }
            else {
                this.commandsList = list || {};
            }
        });
    }
    /**********  Utility Methods  ***************/
    /** True if the current access level is enough to run `command`. */
    checkAccess(command) {
        const entry = this.commandsList[command];
        return !!(entry && this.level <= entry.level);
    }
    /**
     * Execute a command and resolve with its `resultData`. Rejects on a server error or timeout.
     */
    command(command, params) {
        return this.send(command, params).then((resp) => (resp && resp.resultData));
    }
    /**
     * Send one command and resolve with the full decoded response (including `clientId`).
     *
     * The `req` sequence is captured synchronously (call order), and the whole
     * "encrypt → write" step is serialized on a FIFO chain, so frames always leave the wire
     * in `reqSeq` order even when several commands are in flight and WebCrypto resolves out of
     * order. A failed write rejects this command's promise (and the channel must be reset).
     */
    send(command, data) {
        if (!this.connected)
            return Promise.reject(new Error('Socket is closed'));
        const _pkgIndex = this.pkgIndex++;
        const reqSeq = this.cipher ? this.reqSeq++ : 0;
        const payload = JSON.stringify({ command, _pkgIndex, data });
        let settle;
        let fail;
        const result = new Promise((resolve, reject) => { settle = resolve; fail = reject; });
        // Register the response slot + timeout before flushing the write (a fast reply can't be lost).
        this.queue.set(_pkgIndex, { resolve: settle, reject: fail });
        this.queueTimeout.set(_pkgIndex, setTimeout(() => {
            this.dropResponse(_pkgIndex);
            fail(new Error(`Timeout waiting for response #${_pkgIndex} (${this.timeout}ms)`));
        }, this.timeout));
        const job = () => __awaiter(this, void 0, void 0, function* () {
            const text = this.cipher
                ? yield frameEncrypt(payload, this.ek, this.clientId, reqSeq, 'req', this.session)
                : payload;
            this.transportSend(text);
        });
        const runJob = this.sendChain.then(() => job());
        this.sendChain = runJob.catch((e) => {
            const err = e instanceof Error ? e : new Error(String(e));
            this.dropResponse(_pkgIndex);
            fail(err);
        });
        return result;
    }
    dropResponse(_pkgIndex) {
        const timer = this.queueTimeout.get(_pkgIndex);
        if (timer)
            clearTimeout(timer);
        this.queue.delete(_pkgIndex);
        this.queueTimeout.delete(_pkgIndex);
    }
    /** Convert a server error payload into a proper Error instance (message + copied fields). */
    errorify(error) {
        const message = (error && (error.message || error.errorId || error.error || error.code)) || 'VRack2 error';
        const result = new Error(typeof message === 'string' ? message : JSON.stringify(message));
        if (error && typeof error === 'object') {
            for (const key of Object.getOwnPropertyNames(error)) {
                try {
                    result[key] = error[key];
                }
                catch ( /* non-writable, ignore */_a) { /* non-writable, ignore */ }
            }
            result.message = message;
        }
        return result;
    }
}
exports.default = VRackRemote;
