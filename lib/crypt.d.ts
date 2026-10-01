export declare class V2Crypto {
    private readonly subtle;
    /** Pass a `SubtleCrypto` to inject a fake for tests; defaults to the global WebCrypto. */
    constructor(subtle?: SubtleCrypto);
    /** Import an ECDH P-256 private key from PEM (PKCS#8). */
    importEcdhPrivateKey(pem: string): Promise<CryptoKey>;
    /** Import a peer ECDH P-256 public key from PEM(SPKI) or base64url(SPKI). */
    importEcdhPublicKey(serverPub: string): Promise<CryptoKey>;
    /** ECDH shared secret (32 bytes) from a private key and a peer public key. */
    deriveShared(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array>;
    /** HKDF-SHA256 key expansion to 32 bytes. */
    hkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array>;
    /** Wrap a 32-byte key into an AES-256-GCM key. */
    aesGcmKey(ikm: Uint8Array): Promise<CryptoKey>;
    /** `ecdh` mode: `ek = HKDF(ikm=ECDH(priv, serverPub), salt=∅, info="vrack2/v2/ek")`. */
    deriveEcdhChannelKey(clientPrivPem: string, serverPub: string): Promise<CryptoKey>;
    /** `legacy` mode: `ek = HKDF(ikm=secret, salt="vrack2/v2", info="vrack2/v2/ek")`. */
    deriveLegacyChannelKey(secret: string): Promise<CryptoKey>;
    /** Encrypt a payload into a frame: `base64url(12-byte nonce ‖ ciphertext ‖ 16-byte tag)`. */
    frameEncrypt(ek: CryptoKey, payload: string, clientId: number, seq: number, dir: 'req' | 'res', session: string): Promise<string>;
    /** Decrypt a frame back into a payload. Throws on a bad tag / AAD / seq / key. */
    frameDecrypt(ek: CryptoKey, frame: string, clientId: number, seq: number, dir: 'req' | 'res', session: string): Promise<string>;
    /** AAD binding a frame to one session / direction / sequence. Must match the server exactly. */
    private static aad;
}
