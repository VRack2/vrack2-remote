/*
 * Copyright © 2022 Boris Bobylev. All rights reserved.
 * Licensed under the Apache License, Version 2.0
 */

/** Base transport class (protocol logic). Extend it or use a concrete transport below. */
export { default as VRackRemote } from './VRackRemote'
/** Concrete WebSocket/WebSocket-over-WS transport — the ready-to-use client (default export). */
export { default as VRackRemoteWeb } from './VRackRemoteWeb'
/** All VRack2 v2 cryptography (ECDH / HKDF / AES-256-GCM) isolated from the transport. */
export { V2Crypto } from './crypt'
/** A single decoded VRack2 message (request echo / response / broadcast). */
export type { VRack2Message } from './VRackRemote'

/** Default export: the ready-to-use WebSocket client. */
export { default } from './VRackRemoteWeb'
