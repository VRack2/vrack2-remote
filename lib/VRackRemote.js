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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_js_1 = __importDefault(require("crypto-js"));
const events_1 = require("events");
class VRackRemote extends events_1.EventEmitter {
    /**
     * VRack2 transport class
    */
    constructor(key = 'default', privateKey = '') {
        super();
        this.key = 'default';
        this.privateKey = '';
        this.pkgIndex = 1000;
        this.level = 1000;
        this.timeout = 30000;
        this.connected = false;
        this.connection = false;
        this.disconnected = false;
        this.cipher = false;
        this.commandsList = {};
        this.channels = new Map();
        this.queue = new Map();
        this.queueTimeout = new Map();
        this.setKey(key);
        this.setPrivateKey(privateKey);
    }
    setKey(key = 'default') {
        this.key = key;
    }
    setPrivateKey(privateKey = '') {
        this.privateKey = privateKey;
    }
    /**********  Transport events  ***************/
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
        this.channels.clear();
        this.emit('close');
    }
    transportOnError(error) {
        this.emit('error', error);
    }
    transportOnMessage(data) {
        if (this.cipher)
            data = this.decipherData(data);
        const remoteData = JSON.parse(data);
        if (remoteData._pkgIndex) {
            if (this.queue.has(remoteData._pkgIndex)) {
                clearTimeout(this.queueTimeout.get(remoteData._pkgIndex));
                var func = this.queue.get(remoteData._pkgIndex);
                if (func && remoteData.result === 'error') {
                    func.reject(this.errorify(remoteData.resultData));
                }
                else if (func) {
                    func.resolve(remoteData.resultData);
                }
                this.queue.delete(remoteData._pkgIndex);
                this.queueTimeout.delete(remoteData._pkgIndex);
            }
        }
        else if (remoteData.command === 'broadcast') {
            if (this.channels.has(remoteData.target)) {
                const cb = this.channels.get(remoteData.target);
                if (cb)
                    cb(remoteData);
            }
        }
    }
    /**
     * Redefinition for transport
    */
    transportSend(data) {
    }
    /**
     * Redefinition for transport
    */
    transportDisconnect() {
    }
    /**
     * Basic Api command
     **/
    /**
     * Join to broadcastig channel
     *
     * @param channel  Channel name
     * @param cb  Callback broadcast function
     *
    */
    channelJoin(channel, cb) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = this.command('channelJoin', { channel: channel });
            this.channels.set(channel, cb);
            return result;
        });
    }
    /**
     * Leave broadcasting channel
     *
     * @param channel Channel name
    */
    channelLeave(channel) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.command('channelLeave', { channel: channel });
            this.channels.delete(channel);
            return result;
        });
    }
    /**
     * Autorization command functions
    */
    apiKeyAuth() {
        return __awaiter(this, void 0, void 0, function* () {
            var result = yield this.command('apiKeyAuth', { key: this.key });
            if (result.cipher) {
                result = yield this.command('apiPrivateAuth', { verify: this.cipherData(result.verify).toString() });
            }
            this.level = result.level;
            this.cipher = result.cipher;
            return result;
        });
    }
    commandsListUpdate() {
        return __awaiter(this, void 0, void 0, function* () {
            this.commandsList = yield this.command('commandsList', {});
        });
    }
    /**
     * Check level access command
    */
    checkAccess(command) {
        if (this.commandsList[command] &&
            this.level <= this.commandsList[command].level)
            return true;
        return false;
    }
    /**
     * cipher data for server
    */
    cipherData(data) {
        return crypto_js_1.default.AES.encrypt(data, crypto_js_1.default.enc.Utf8.parse(this.privateKey), {
            iv: crypto_js_1.default.enc.Utf8.parse(this.key),
            mode: crypto_js_1.default.mode.CBC
        });
    }
    /**
     * decipher raw data from server
     * used if expect private key
     *
    */
    decipherData(data) {
        const res = crypto_js_1.default.AES.decrypt(data, crypto_js_1.default.enc.Utf8.parse(this.privateKey), {
            iv: crypto_js_1.default.enc.Utf8.parse(this.key),
            mode: crypto_js_1.default.mode.CBC
        });
        return res.toString(crypto_js_1.default.enc.Utf8);
    }
    /**
     * Run server async command
     *
     *
     * @param command Server api command (like a serviceShares, apiKeyAdd...)
     * @param params Command params (ever is object like a { param: value... })
    */
    command(command, params) {
        return new Promise((resolve, reject) => {
            const send = { command: command, _pkgIndex: this.pkgIndex++, data: params };
            this.addToQueue(send, resolve, reject);
        });
    }
    /**
     * Add command to queue and send him to server
     *
     * @see command
    */
    addToQueue(params, resolve, reject) {
        this.queue.set(params._pkgIndex, { resolve, reject });
        this.queueTimeout.set(params._pkgIndex, setTimeout(() => {
            reject(new Error('Timeout'));
            this.queue.delete(params._pkgIndex);
            this.queueTimeout.delete(params._pkgIndex);
        }, this.timeout));
        if (!this.connected)
            reject(new Error('Socket is closed'));
        var data = JSON.stringify(params);
        if (this.cipher)
            data = this.cipherData(data).toString();
        this.transportSend(data);
    }
    errorify(error) {
        const result = new Error();
        const keys = Object.getOwnPropertyNames(error);
        for (const key of keys) {
            result[key] = error[key];
        }
        return result;
    }
}
exports.default = VRackRemote;
