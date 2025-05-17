import CryptoJS from 'crypto-js';
import { EventEmitter } from 'events';
export default class VRackRemote extends EventEmitter {
    protected key: string;
    protected privateKey: string;
    protected pkgIndex: number;
    level: number;
    timeout: number;
    connected: boolean;
    connection: boolean;
    disconnected: boolean;
    cipher: boolean;
    commandsList: {
        [key: string]: {
            command: string;
            description: string;
            level: number;
        };
    };
    protected channels: Map<string, (data: any) => void>;
    protected queue: Map<number, {
        resolve: (value: unknown) => void;
        reject: (error: Error) => void;
    }>;
    protected queueTimeout: Map<number, number>;
    /**
     * VRack2 transport class
    */
    constructor(key?: string, privateKey?: string);
    setKey(key?: string): void;
    setPrivateKey(privateKey?: string): void;
    /**********  Transport events  ***************/
    protected transportOnOpen(): void;
    protected transportOnClose(): void;
    protected transportOnError(error: Error): void;
    protected transportOnMessage(data: string): void;
    /**
     * Redefinition for transport
    */
    protected transportSend(data: string): void;
    /**
     * Redefinition for transport
    */
    protected transportDisconnect(): void;
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
    channelJoin(channel: string, cb: (data: any) => void): Promise<any>;
    /**
     * Leave broadcasting channel
     *
     * @param channel Channel name
    */
    channelLeave(channel: string): Promise<any>;
    /**
     * Autorization command functions
    */
    apiKeyAuth(): Promise<any>;
    commandsListUpdate(): Promise<void>;
    /**
     * Check level access command
    */
    checkAccess(command: string): boolean;
    /**
     * cipher data for server
    */
    protected cipherData(data: string): CryptoJS.lib.CipherParams;
    /**
     * decipher raw data from server
     * used if expect private key
     *
    */
    protected decipherData(data: string): string;
    /**
     * Run server async command
     *
     *
     * @param command Server api command (like a serviceShares, apiKeyAdd...)
     * @param params Command params (ever is object like a { param: value... })
    */
    command(command: string, params: any): Promise<any>;
    /**
     * Add command to queue and send him to server
     *
     * @see command
    */
    protected addToQueue(params: {
        command: string;
        _pkgIndex: number;
        data: any;
    }, resolve: (value: unknown) => void, reject: (error: Error) => void): void;
    protected errorify(error: any): Error;
}
