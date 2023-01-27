export interface CryptoPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
  generateKeyPair() : Promise<{ publicKey: string, privateKey: string}>;
  generateSharedSecret(options: {privateKey: string, publicKey: string, salt: string}) : Promise<{ sharedSecret: string }>;
  /*
  ** Generate Random Bytes (Secure)
  **
  ** @returns Bytes as Base64 String
  */
  generateRandomBytes(options: {count: number}) : Promise<{ bytesBase64: string }>;

  /*
  ** Encrypt data with a key using AES-256-GCM
  **
  ** @returns The encrypted data, auth tag and the random IV
  */
  encrypt(options: {key: string, data: string}) : Promise<{ encryptedData: string, tag: string, iv: string }>;
  decrypt(options: {key: string, encryptedData: string, tag: string, iv: string}) : Promise<{unencryptedData: string}>;

  // SHA-512 hashing function, returns hex string
  hash(options: {data: string}) : Promise<{hash: string}>;
}
