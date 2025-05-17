"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const VRackRemote_1 = __importDefault(require("./VRackRemote"));
class VRackRemoteWeb extends VRackRemote_1.default {
    constructor(host = 'ws://localhost:4044', key = 'default', privateKey = '') {
        super(key, privateKey);
        this.host = host;
    }
    connect() {
        return new Promise((resolve, reject) => {
            if (this.connected === true)
                this.transportDisconnect();
            this.connection = true;
            this.emit('connection');
            try {
                this.ws = new WebSocket(this.host);
            }
            catch (error) {
                reject(error);
                return;
            }
            // Owerride
            this.transportSend = (data) => {
                var _a;
                (_a = this.ws) === null || _a === void 0 ? void 0 : _a.send(data);
            };
            // Owerride
            this.transportDisconnect = () => {
                var _a;
                (_a = this.ws) === null || _a === void 0 ? void 0 : _a.close();
            };
            this.ws.onopen = () => {
                this.transportOnOpen();
                resolve('success');
            };
            this.ws.onerror = (error) => {
                this.transportOnError(new Error('Websocket error'));
            };
            this.ws.onclose = () => {
                this.transportOnClose();
                this.ws = undefined;
                reject(new Error('Connection closed'));
            };
            this.ws.onmessage = (evt) => {
                this.transportOnMessage(evt.data);
            };
        });
    }
    disconnect() {
        var _a;
        (_a = this.ws) === null || _a === void 0 ? void 0 : _a.close();
    }
}
exports.default = VRackRemoteWeb;
