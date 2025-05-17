import CryptoJS from 'crypto-js'
import { EventEmitter } from 'events'

/**
 * VRackRemote - A transport class for VRack2 remote communication
 * 
 * This class handles encrypted communication with VRack2 servers, including:
 * - Connection management
 * - Command execution with queuing
 * - Channel-based broadcasting
 * - Authentication
 * - Data encryption/decryption
 */
export default class VRackRemote extends EventEmitter {
    // Protected properties
    protected key = 'default'                      // Default API key
    protected privateKey = ''                      // Private key for encryption
    protected pkgIndex = 1000                      // Package index counter
    protected channels = new Map<string, (data: any) => void>()  // Active channels
    protected queue = new Map<number, {            // Command queue
        resolve: (value: unknown) => void,
        reject: (error: Error) => void
    }>()
    protected queueTimeout = new Map<number, number>() // Queue timeouts

    // Public properties
    level = 1000                                   // Access level
    timeout = 30000                                // Command timeout in ms
    connected = false                              // Connection status
    connection = false                             // Connection in progress flag
    cipher = false                                 // Encryption enabled flag
    commandsList: {
        [key: string]: {              // Available commands list
            command: string,
            description: string,
            level: number
        }
    } = {}

    /**
     * Constructor
     * 
     * @param key - API key (default: 'default')
     * @param privateKey - Private key for encryption (default: '')
     */
    constructor(key = 'default', privateKey = '') {
        super()
        this.setKey(key)
        this.setPrivateKey(privateKey)
    }

    /**********  Key Management  ***************/

    /**
     * Set the API key
     * 
     * @param key - New API key (default: 'default')
     */
    setKey(key = 'default') {
        this.key = key
    }

    /**
     * Set the private key for encryption
     * 
     * @param privateKey - New private key (default: '')
     */
    setPrivateKey(privateKey = '') {
        this.privateKey = privateKey
    }

    /**********  Transport Events  ***************/

    /**
     * Handle transport connection open
     */
    protected transportOnOpen() {
        this.connected = true
        this.connection = false
        this.emit('open')
    }

    /**
     * Handle transport connection close
     */
    protected transportOnClose() {
        this.connected = false
        this.connection = false
        this.cipher = false
        this.level = 1000
        this.channels.clear()
        this.emit('close')
    }

    /**
     * Handle transport error
     * 
     * @param error - Error object
     */
    protected transportOnError(error: Error) {
        this.emit('error', error)
    }

    /**
     * Handle incoming message
     * 
     * @param data - Received message data
     */
    protected transportOnMessage(data: string) {
        // Decrypt data if encryption is enabled
        if (this.cipher) data = this.decipherData(data)

        const remoteData = JSON.parse(data)

        // Handle command responses
        if (remoteData._pkgIndex) {
            if (this.queue.has(remoteData._pkgIndex)) {
                clearTimeout(this.queueTimeout.get(remoteData._pkgIndex))
                const func = this.queue.get(remoteData._pkgIndex)

                if (func && remoteData.result === 'error') {
                    func.reject(this.errorify(remoteData.resultData))
                } else if (func) {
                    func.resolve(remoteData.resultData)
                }

                this.queue.delete(remoteData._pkgIndex)
                this.queueTimeout.delete(remoteData._pkgIndex)
            }
        }
        // Handle broadcast messages
        else if (remoteData.command === 'broadcast') {
            if (this.channels.has(remoteData.target)) {
                const cb = this.channels.get(remoteData.target)
                if (cb) cb(remoteData)
            }
        }
    }

    /**********  Transport Methods (To be overridden)  ***************/

    /**
     * Send data through transport
     * 
     * @param data - Data to send
     */
    protected transportSend(data: string) {
        // To be implemented by child classes
    }

    /**
     * Disconnect transport
     */
    protected transportDisconnect() {
        // To be implemented by child classes
    }

    /**********  Channel Methods  ***************/

    /**
     * Join a broadcast channel
     * 
     * @param channel - Channel name
     * @param cb - Callback function for broadcast messages
     * @returns Promise with join result
     */
    async channelJoin(channel: string, cb: (data: any) => void) {
        const result = this.command('channelJoin', { channel: channel })
        this.channels.set(channel, cb)
        return result
    }

    /**
     * Leave a broadcast channel
     * 
     * @param channel - Channel name
     * @returns Promise with leave result
     */
    async channelLeave(channel: string) {
        const result = await this.command('channelLeave', { channel: channel })
        this.channels.delete(channel)
        return result
    }

    /**********  Authentication Methods  ***************/

    /**
     * Authenticate using API key
     * 
     * @returns Promise with authentication result
     */
    async apiKeyAuth() {
        let result = await this.command('apiKeyAuth', { key: this.key })

        // If server requires additional private key authentication
        if (result.cipher) {
            result = await this.command('apiPrivateAuth', {
                verify: this.cipherData(result.verify).toString()
            })
        }

        this.level = result.level
        this.cipher = result.cipher
        return result
    }

    /**
     * Update available commands list from server
     * 
     * @returns Promise with commands list
     */
    async commandsListUpdate() {
        this.commandsList = await this.command('commandsList', {})
    }

    /**********  Utility Methods  ***************/

    /**
     * Check if current access level allows executing a command
     * 
     * @param command - Command name to check
     * @returns True if access is allowed, false otherwise
     */
    checkAccess(command: string) {
        if (this.commandsList[command] &&
            this.level <= this.commandsList[command].level) return true
        return false
    }

    /**
     * Encrypt data using AES-CBC
     * 
     * @param data - Data to encrypt
     * @returns Encrypted data
     */
    protected cipherData(data: string) {
        return CryptoJS.AES.encrypt(data, CryptoJS.enc.Utf8.parse(this.privateKey), {
            iv: CryptoJS.enc.Utf8.parse(this.key),
            mode: CryptoJS.mode.CBC
        })
    }

    /**
     * Decrypt data using AES-CBC
     * 
     * @param data - Data to decrypt
     * @returns Decrypted data
     */
    protected decipherData(data: string) {
        const res = CryptoJS.AES.decrypt(data, CryptoJS.enc.Utf8.parse(this.privateKey), {
            iv: CryptoJS.enc.Utf8.parse(this.key),
            mode: CryptoJS.mode.CBC
        })
        return res.toString(CryptoJS.enc.Utf8)
    }

    /**
     * Execute a remote command
     * 
     * @param command - Command name
     * @param params - Command parameters
     * @returns Promise with command result
     */
    command(command: string, params: any): Promise<any> {
        return new Promise((resolve, reject) => {
            const send = {
                command: command,
                _pkgIndex: this.pkgIndex++,
                data: params
            }
            this.addToQueue(send, resolve, reject)
        })
    }

    /**
     * Add command to execution queue
     * 
     * @param params - Command parameters including package index
     * @param resolve - Promise resolve function
     * @param reject - Promise reject function
     */
    protected addToQueue(
        params: { command: string, _pkgIndex: number, data: any },
        resolve: (value: unknown) => void,
        reject: (error: Error) => void
    ) {
        // Add to queue
        this.queue.set(params._pkgIndex, { resolve, reject })

        // Set timeout
        this.queueTimeout.set(params._pkgIndex, setTimeout(() => {
            reject(new Error('Timeout'))
            this.queue.delete(params._pkgIndex)
            this.queueTimeout.delete(params._pkgIndex)
        }, this.timeout))

        // Send immediately if connected
        if (!this.connected) reject(new Error('Socket is closed'))

        let data = JSON.stringify(params)
        if (this.cipher) data = this.cipherData(data).toString()
        this.transportSend(data)
    }

    /**
     * Convert error-like object to Error instance
     * 
     * @param error - Error object to convert
     * @returns Proper Error instance
     */
    protected errorify(error: any) {
        const result = new Error()
        const keys = Object.getOwnPropertyNames(error)
        for (const key of keys) {
            result[key as keyof Error] = error[key]
        }
        return result
    }
}