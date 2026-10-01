import { EventEmitter } from 'events'
import { V2Crypto } from './crypt'

/*
 * VRackRemote — VRack2 client transport (new "v2" protocol).
 *
 * The channel is protected with standardized primitives (see ./crypt.ts for the crypto class):
 *   • asymmetric key material — ECDH P-256
 *   • channel key `ek`        — HKDF-SHA256 (32 bytes)
 *   • authenticated frames    — AES-256-GCM  (base64url(nonce ‖ ciphertext ‖ tag))
 *
 * Every frame is bound to one session via AAD `{ c: clientId, s: seq, d: req|res, v: session }`,
 * which defeats replay and cross-session/cross-direction transfer. The crypto backend is the
 * standard WebCrypto API (`crypto.subtle`), so the same code runs in a browser (secure context)
 * and in Node.js (>= 15).
 *
 * Three key modes are supported automatically (decided by the `apiKeyAuth` answer):
 *   • plain      — no `verify`        -> channel stays plain JSON
 *   • ecdh       — `verify`+`serverPub`-> ECDH channel, GCM frames (modern)
 *   • legacy     — `verify` only       -> shared-secret HKDF channel, GCM frames (compat)
 */

/** A single decoded VRack2 message (request echo / response / broadcast). */
export interface VRack2Message {
    command?: string
    _pkgIndex?: number
    result?: 'success' | 'error' | string
    resultData?: any
    /** Assigned by the server on the connection (present in apiKeyAuth answers). */
    clientId?: number
    target?: string
    data?: any
    [key: string]: any
}

export default class VRackRemote extends EventEmitter {
    // Credentials
    protected key = 'default'               // KID (public key identifier)
    protected privateKey = ''              // PEM private key (ECDH) or shared secret (legacy)

    // Bookkeeping
    protected pkgIndex = 1000              // _pkgIndex counter (request/response correlation)
    protected channels = new Map<string, (data: any) => void>()
    protected queue = new Map<number, { resolve: (value: any) => void, reject: (error: Error) => void }>()
    protected queueTimeout = new Map<number, ReturnType<typeof setTimeout>>()
    private sendChain: Promise<unknown> = Promise.resolve()  // serializes wire writes so frame order == seq order

    // Crypto (created lazily — plain keys never need it, and it must not break their construction)
    private _v2?: V2Crypto
    private get v2(): V2Crypto {
        return this._v2 ?? (this._v2 = new V2Crypto())
    }

    // Public state
    level = 1000                           // access level (1/2/3/1000)
    timeout = 30000                        // command timeout (ms)
    connected = false                      // connection is up
    connection = false                     // connection in progress
    cipher = false                         // channel is encrypted (GCM frames)
    mode: 'plain' | 'ecdh' | 'legacy' | null = null  // negotiated key mode
    commandsList: { [command: string]: { command: string, description: string, level: number, [k: string]: any } } = {}

    // Negotiated session state (set during apiKeyAuth)
    clientId: number | null = null         // server-assigned connection id (AAD `c`)
    session: string | null = null          // server challenge `verify` (AAD `v`)
    ek: CryptoKey | null = null            // AES-256-GCM channel key (set after proof)
    reqSeq = 1                             // outbound (req) sequence, starts at 1
    resSeq = 1                             // inbound  (res) sequence, starts at 1

    constructor(key = 'default', privateKey = '') {
        super()
        this.setKey(key)
        this.setPrivateKey(privateKey)
    }

    /**********  Key Management  ***************/

    /** Set the KID (public key identifier). */
    setKey(key = 'default') {
        this.key = key
    }

    /** Set the private key: PEM (ECDH) or shared secret (legacy). Mode is auto-detected from the server answer. */
    setPrivateKey(privateKey = '') {
        this.privateKey = privateKey
    }

    /**********  Transport Events  ***************/

    protected transportOnOpen() {
        this.connected = true
        this.connection = false
        this.emit('open')
    }

    protected transportOnClose() {
        this.connected = false
        this.connection = false
        this.cipher = false
        this.level = 1000
        this.mode = null
        this.clientId = null
        this.session = null
        this.ek = null
        this.reqSeq = 1
        this.resSeq = 1
        this.channels.clear()
        this.emit('close')
    }

    protected transportOnError(error: Error) {
        this.emit('error', error)
    }

    /**
     * Handle an incoming message. If the channel is cipher-enabled the message is a GCM frame
     * (the raw base64url string); otherwise it is plain JSON (handshake or a plain key).
     */
    protected async transportOnMessage(data: string) {
        let text = data
        if (this.cipher) {
            const seq = this.resSeq++
            try {
                text = await this.v2.frameDecrypt(this.ek as CryptoKey, data, this.clientId as number, seq, 'res', this.session as string)
            } catch (error) {
                // A failing auth tag means the channel is corrupted (replay / tamper / seq skew):
                // surface it and stop trusting the connection.
                this.transportOnError(error instanceof Error ? error : new Error('Frame decrypt failed'))
                return
            }
        }

        let remoteData: VRack2Message
        try {
            remoteData = JSON.parse(text)
        } catch (error) {
            this.transportOnError(error instanceof Error ? error : new Error('Invalid JSON from server'))
            return
        }

        if (remoteData._pkgIndex != null && this.queue.has(remoteData._pkgIndex)) {
            const func = this.queue.get(remoteData._pkgIndex) as { resolve: (v: any) => void, reject: (e: Error) => void }
            const timer = this.queueTimeout.get(remoteData._pkgIndex)
            if (timer) clearTimeout(timer)
            this.queue.delete(remoteData._pkgIndex)
            this.queueTimeout.delete(remoteData._pkgIndex)
            if (remoteData.result === 'error') func.reject(this.errorify(remoteData.resultData))
            else func.resolve(remoteData)
        } else if (remoteData.command === 'broadcast') {
            const cb = this.channels.get(remoteData.target as string)
            if (cb) cb(remoteData)
        }
    }

    /**********  Transport Methods (To be overridden)  ***************/

    protected transportSend(data: string) {
        // Implemented by a concrete transport (e.g. VRackRemoteWeb over WebSocket).
    }

    protected transportDisconnect() {
        // Implemented by a concrete transport.
    }

    /**********  Channel Methods  ***************/

    /** Join a broadcast channel. */
    async channelJoin(channel: string, cb: (data: any) => void) {
        const result = this.command('channelJoin', { channel })
        this.channels.set(channel, cb)
        return result
    }

    /** Leave a broadcast channel. */
    async channelLeave(channel: string) {
        const result = await this.command('channelLeave', { channel })
        this.channels.delete(channel)
        return result
    }

    /**********  Authentication Methods  ***************/

    /**
     * Authenticate. Sends `apiKeyAuth`; if the key requires a cipher channel it performs the
     * `apiPrivateAuth` proof (encrypts the server challenge as the first req frame) and derives
     * the channel key. After a successful proof the channel is encrypted.
     */
    async apiKeyAuth(): Promise<any> {
        const auth = await this.send('apiKeyAuth', { key: this.key })
        const rd = (auth.resultData || {}) as any
        this.clientId = auth.clientId != null ? auth.clientId : null
        this.session = null
        this.ek = null
        this.reqSeq = 1
        this.resSeq = 1

        if (!rd.verify) {
            // Plain key — the channel is already usable, no cipher.
            this.mode = 'plain'
            this.cipher = false
            this.level = rd.level
            return rd
        }

        // Cipher key — need the secret to derive the channel key.
        if (!this.privateKey) throw new Error('This key requires encryption (verify), but no private key was set (setPrivateKey)')
        this.session = rd.verify

        if (rd.serverPub) this.ek = await this.v2.deriveEcdhChannelKey(this.privateKey, rd.serverPub)
        else this.ek = await this.v2.deriveLegacyChannelKey(this.privateKey)
        this.mode = rd.serverPub ? 'ecdh' : 'legacy'

        // Proof: encrypt the server challenge as the first outbound frame (req seq = 1).
        // The apiPrivateAuth request and its answer are plain JSON; only after this do we frame.
        const frame = await this.v2.frameEncrypt(this.ek, rd.verify, this.clientId as number, 1, 'req', rd.verify)
        const proof = await this.send('apiPrivateAuth', { frame })
        this.cipher = true
        this.level = proof.resultData ? proof.resultData.level : this.level
        this.reqSeq = 2 // proof consumed req seq 1; next command is 2
        this.resSeq = 1 // the proof answer is plain, so the first framed answer is res seq 1
        return proof.resultData
    }

    /** Update the available-commands list from the server. */
    async commandsListUpdate() {
        const list = await this.command('commandsList', {})
        if (Array.isArray(list)) {
            const obj: typeof this.commandsList = {}
            for (const item of list) {
                if (item && item.command) obj[item.command] = item
            }
            this.commandsList = obj
        } else {
            this.commandsList = list || {}
        }
    }

    /**********  Utility Methods  ***************/

    /** True if the current access level is enough to run `command`. */
    checkAccess(command: string) {
        const entry = this.commandsList[command]
        return !!(entry && this.level <= entry.level)
    }

    /**
     * Execute a command and resolve with its `resultData`. Rejects on a server error or timeout.
     */
    command(command: string, params: any): Promise<any> {
        return this.send(command, params).then((resp) => (resp && resp.resultData))
    }

    /**
     * Send one command and resolve with the full decoded response (including `clientId`).
     *
     * The `req` sequence is captured synchronously (call order), and the whole
     * "encrypt → write" step is serialized on a FIFO chain, so frames always leave the wire
     * in `reqSeq` order even when several commands are in flight and WebCrypto resolves out of
     * order. A failed write rejects this command's promise (and the channel must be reset).
     */
    protected send(command: string, data: any): Promise<VRack2Message> {
        if (!this.connected) return Promise.reject(new Error('Socket is closed'))

        const _pkgIndex = this.pkgIndex++
        const reqSeq = this.cipher ? this.reqSeq++ : 0
        const payload = JSON.stringify({ command, _pkgIndex, data })

        let settle!: (resp: VRack2Message) => void
        let fail!: (err: Error) => void
        const result = new Promise<VRack2Message>((resolve, reject) => { settle = resolve; fail = reject })

        // Register the response slot + timeout before flushing the write (a fast reply can't be lost).
        this.queue.set(_pkgIndex, { resolve: settle, reject: fail })
        this.queueTimeout.set(_pkgIndex, setTimeout(() => {
            this.dropResponse(_pkgIndex)
            fail(new Error(`Timeout waiting for response #${_pkgIndex} (${this.timeout}ms)`))
        }, this.timeout))

        const job = async () => {
            const text = this.cipher
                ? await this.v2.frameEncrypt(this.ek as CryptoKey, payload, this.clientId as number, reqSeq, 'req', this.session as string)
                : payload
            this.transportSend(text)
        }
        const runJob = this.sendChain.then(() => job())
        this.sendChain = runJob.catch((e) => {
            const err = e instanceof Error ? e : new Error(String(e))
            this.dropResponse(_pkgIndex)
            fail(err)
        })

        return result
    }

    private dropResponse(_pkgIndex: number) {
        const timer = this.queueTimeout.get(_pkgIndex)
        if (timer) clearTimeout(timer)
        this.queue.delete(_pkgIndex)
        this.queueTimeout.delete(_pkgIndex)
    }

    /** Convert a server error payload into a proper Error instance (message + copied fields). */
    protected errorify(error: any): Error {
        const message = (error && (error.message || error.errorId || error.error || error.code)) || 'VRack2 error'
        const result: any = new Error(typeof message === 'string' ? message : JSON.stringify(message))
        if (error && typeof error === 'object') {
            for (const key of Object.getOwnPropertyNames(error)) {
                try { result[key] = (error as any)[key] } catch { /* non-writable, ignore */ }
            }
            result.message = message
        }
        return result
    }
}
