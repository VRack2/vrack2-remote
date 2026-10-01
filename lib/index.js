"use strict";
/*
 * Copyright © 2022 Boris Bobylev. All rights reserved.
 * Licensed under the Apache License, Version 2.0
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = exports.V2Crypto = exports.VRackRemoteWeb = exports.VRackRemote = void 0;
/** Base transport class (protocol logic). Extend it or use a concrete transport below. */
var VRackRemote_1 = require("./VRackRemote");
Object.defineProperty(exports, "VRackRemote", { enumerable: true, get: function () { return __importDefault(VRackRemote_1).default; } });
/** Concrete WebSocket/WebSocket-over-WS transport — the ready-to-use client (default export). */
var VRackRemoteWeb_1 = require("./VRackRemoteWeb");
Object.defineProperty(exports, "VRackRemoteWeb", { enumerable: true, get: function () { return __importDefault(VRackRemoteWeb_1).default; } });
/** All VRack2 v2 cryptography (ECDH / HKDF / AES-256-GCM) isolated from the transport. */
var crypt_1 = require("./crypt");
Object.defineProperty(exports, "V2Crypto", { enumerable: true, get: function () { return crypt_1.V2Crypto; } });
/** Default export: the ready-to-use WebSocket client. */
var VRackRemoteWeb_2 = require("./VRackRemoteWeb");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return __importDefault(VRackRemoteWeb_2).default; } });
