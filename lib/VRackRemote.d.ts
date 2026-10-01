import { EventEmitter } from 'events';
/** A single decoded VRack2 message (request echo / response / broadcast). */
export interface VRack2Message {
    command?: string;
    _pkgIndex?: number;
    result?: 'success' | 'error' | string;
    resultData?: any;
    /** Assigned by the server on the connection (present in apiKeyAuth answers). */
    clientId?: number;
    target?: string;
    data?: any;
    [key: string]: any;
}
export default class VRackRemote extends EventEmitter {
    protected key: string;
    protected privateKey: string;
    protected pkgIndex: number;
    protected channels: Map<string, (data: any) => void>;
    protected queue: Map<number, {
        resolve: (value: any) => void;
        reject: (error: Error) => void;
    }>;
    protected queueTimeout: Map<number, number>;
    private sendChain;
    level: number;
    timeout: number;
    connected: boolean;
    connection: boolean;
    cipher: boolean;
    mode: 'plain' | 'ecdh' | 'legacy' | null;
    commandsList: {
        [command: string]: {
            command: string;
            description: string;
            level: number;
            [k: string]: any;
        };
    };
    clientId: number | null;
    session: string | null;
    ek: Uint8Array | null;
    reqSeq: number;
    resSeq: number;
    constructor(key?: string, privateKey?: string);
    /**********  Key Management  ***************/
    /** Set the KID (public key identifier). */
    setKey(key?: string): void;
    /** Set the private key: PEM (ECDH) or shared secret (legacy). Mode is auto-detected from the server answer. */
    setPrivateKey(privateKey?: string): void;
    /**********  Transport Events  ***************/
    protected transportOnOpen(): void;
    protected transportOnClose(): void;
    protected transportOnError(error: Error): void;
    /**
     * Handle an incoming message. If the channel is cipher-enabled the message is a GCM frame
     * (the raw base64url string); otherwise it is plain JSON (handshake or a plain key).
     */
    protected transportOnMessage(data: string): Promise<void>;
    /**********  Transport Methods (To be overridden)  ***************/
    protected transportSend(data: string): void;
    protected transportDisconnect(): void;
    /**********  Channel Methods  ***************/
    /** Join a broadcast channel. */
    channelJoin(channel: string, cb: (data: any) => void): Promise<any>;
    /** Leave a broadcast channel. */
    channelLeave(channel: string): Promise<any>;
    /**********  Authentication Methods  ***************/
    /**
     * Authenticate. Sends `apiKeyAuth`; if the key requires a cipher channel it performs the
     * `apiPrivateAuth` proof (encrypts the server challenge as the first req frame) and derives
     * the channel key. After a successful proof the channel is encrypted.
     */
    apiKeyAuth(): Promise<any>;
    /** Update the available-commands list from the server. */
    commandsListUpdate(): Promise<void>;
    /**********  Utility Methods  ***************/
    /** True if the current access level is enough to run `command`. */
    checkAccess(command: string): boolean;
    /**
     * Execute a command and resolve with its `resultData`. Rejects on a server error or timeout.
     */
    command(command: string, params: any): Promise<any>;
    /**
     * Send one command and resolve with the full decoded response (including `clientId`).
     *
     * The `req` sequence is captured synchronously (call order), and the whole
     * "encrypt → write" step is serialized on a FIFO chain, so frames always leave the wire
     * in `reqSeq` order even when several commands are in flight and WebCrypto resolves out of
     * order. A failed write rejects this command's promise (and the channel must be reset).
     */
    protected send(command: string, data: any): Promise<VRack2Message>;
    private dropResponse;
    /** Convert a server error payload into a proper Error instance (message + copied fields). */
    protected errorify(error: any): Error;
}
