export interface CryptoPlugin {
    echo(options: {
        value: string;
    }): Promise<{
        value: string;
    }>;
    generateKeyPair(): Promise<{
        publicKey: string;
        privateKey: string;
    }>;
    generateSharedSecret(options: {
        privateKey: string;
        publicKey: string;
        salt: string;
    }): Promise<{
        sharedSecret: string;
    }>;
    generateRandomBytes(options: {
        count: number;
    }): Promise<{
        bytesBase64: string;
    }>;
    encrypt(options: {
        key: string;
        data: string;
    }): Promise<{
        encryptedData: string;
        tag: string;
        iv: string;
    }>;
    decrypt(options: {
        key: string;
        encryptedData: string;
        tag: string;
        iv: string;
    }): Promise<{
        unencryptedData: string;
    }>;
}
