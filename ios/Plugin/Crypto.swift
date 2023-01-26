import Foundation
import CryptoKit

@available(iOS 14.0, *)
@objc public class Crypto: NSObject {
    @objc public func echo(_ value: String) -> String {
        print(value)
        return value
    }
    
    @objc public func generateKeyPair() -> NSArray {
        let newKey = CryptoKit.P256.KeyAgreement.PrivateKey()
        return [newKey.publicKey.derRepresentation.base64EncodedString(), newKey.derRepresentation.base64EncodedString()];
    }
    
    @objc public func generateSharedSecret(_ privateKey: String, _ publicKey: String, _ salt : String) throws -> String {
        guard let privateKeyBytes = Data(base64Encoded: privateKey) else {
            throw NSError(domain: "Decoding Private Key B64", code: 0);
        }
        
        guard let publicKeyBytes = Data(base64Encoded: publicKey) else {
            throw NSError(domain: "Decoding Public Key B64", code: 0);
        }
        
        guard let saltBytes = Data(base64Encoded: salt) else {
            throw NSError(domain: "Decoding Salt", code: 0);
        }
        
        let privateKeyDER = try CryptoKit.P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyBytes);
        let publicKeyDER = try CryptoKit.P256.KeyAgreement.PublicKey(derRepresentation: publicKeyBytes);
            
        let sharedSecret = try privateKeyDER.sharedSecretFromKeyAgreement(with: publicKeyDER);
            
        let finalSecret = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: saltBytes, outputByteCount: 32);
            
        return finalSecret.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString()
        };
    }
    
    @objc public func encrypt(_ key : String, _ unencryptedData : String) throws -> NSArray {
        guard let keyBytes = Data(base64Encoded: key) else {
            throw NSError(domain: "Can't decode key bytes", code: 0);
        }
        
        guard let unencryptedBytes = unencryptedData.data(using: .utf8) else {
            throw NSError(domain: "Can't decode data to bytes", code: 0);
        }
        
        let key = SymmetricKey(data: keyBytes);

        // apple can generate the random iv)
        let iv = CryptoKit.AES.GCM.Nonce();
        
        let encryptedBox = try CryptoKit.AES.GCM.seal(unencryptedBytes, using: key, nonce: iv);
        
        let ivBase64 = iv.withUnsafeBytes {
            return Data(Array($0)).base64EncodedString();
        }
        
        return [encryptedBox.ciphertext.base64EncodedString(), encryptedBox.tag.base64EncodedString(), encryptedBox.nonce.withUnsafeBytes { Data(Array($0)).base64EncodedString() }];
    }
    
    
    @objc public func decrypt(_ key : String, _ encryptedData : String, _ tag : String, _ iv: String) throws -> String
    {
        guard let keyBytes = Data(base64Encoded: key) else {
            throw NSError(domain: "Can't decode key bytes", code: 0);
        }
        
        guard let encryptedBytes = Data(base64Encoded: encryptedData) else {
            throw NSError(domain: "Can't decode data bytes", code: 0);
        }
        
        guard let tagBytes = Data(base64Encoded: tag) else {
            throw NSError(domain: "Can't decode tag bytes", code: 0);
        }
        
        guard let ivBytes = Data(base64Encoded: iv) else {
            throw NSError(domain: "Can't decode iv bytes", code: 0);
        }
        
        let key = SymmetricKey(data: keyBytes);
        let nonce = try CryptoKit.AES.GCM.Nonce(data: ivBytes);
        
        let sealedBox = try CryptoKit.AES.GCM.SealedBox(nonce: nonce, ciphertext: encryptedBytes, tag: tagBytes);
        
        let unencryptedBytes = try CryptoKit.AES.GCM.open(sealedBox, using: key);
        
        return String(bytes: unencryptedBytes, encoding: .utf8)!;
    }
    
    @objc public func generateRandomBytes(_ count: Int) throws -> String {
        var bytes = [Int8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        if status == errSecSuccess {
            return bytes.withUnsafeBytes {
                return Data(Array($0)).base64EncodedString();
            }
        } else {
            throw NSError(domain: "Random Bytes Failed", code: 0);
        }
    }
}
