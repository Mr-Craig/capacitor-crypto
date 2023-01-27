import { WebPlugin } from '@capacitor/core';
export class CryptoWeb extends WebPlugin {
    async echo(options) {
        console.log('ECHO', options);
        return options;
    }
    async generateKeyPair() {
        if (typeof (window.crypto.subtle) === "undefined") {
            throw this.unavailable("Subtle API not available");
        }
        if (!window.isSecureContext) {
            throw this.unavailable("Unable to use CryptoAPI, not in secure context!");
        }
        let generatedKeys = await window.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-256"
        }, true, ["deriveKey"]);
        let exportedPrivateKey = await window.crypto.subtle.exportKey("pkcs8", generatedKeys.privateKey);
        let exportedPublicKey = await window.crypto.subtle.exportKey("spki", generatedKeys.publicKey);
        let publicKeyDER = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));
        let privateKeyDER = btoa(String.fromCharCode(...new Uint8Array(exportedPrivateKey)));
        return {
            publicKey: publicKeyDER,
            privateKey: privateKeyDER
        };
    }
    async generateSharedSecret(options) {
        if (typeof (window.crypto.subtle) === "undefined") {
            throw this.unavailable("Subtle API not available");
        }
        if (!window.isSecureContext) {
            throw this.unavailable("Unable to use CryptoAPI, not in secure context!");
        }
        let privateKeyBuffer = Uint8Array.from(atob(options.privateKey), x => x.charCodeAt(0));
        let publicKeyBuffer = Uint8Array.from(atob(options.publicKey), x => x.charCodeAt(0));
        this.unavailable(publicKeyBuffer.toString() + " " + privateKeyBuffer.toString());
        let privateKeyImported = await window.crypto.subtle.importKey("pkcs8", privateKeyBuffer, {
            name: "ECDH",
            namedCurve: "P-256"
        }, false, ["deriveBits"]);
        let publicKeyImported = await window.crypto.subtle.importKey("spki", publicKeyBuffer, {
            name: "ECDH",
            namedCurve: "P-256"
        }, true, []);
        let derivedSharedSecret = await window.crypto.subtle.deriveBits({
            name: "ECDH",
            public: publicKeyImported
        }, privateKeyImported, 256);
        let importedSharedSecret = await window.crypto.subtle.importKey("raw", derivedSharedSecret, "HKDF", false, ['deriveBits']);
        let saltBytes = Uint8Array.from(atob(options.salt), x => x.charCodeAt(0));
        let derivedKey = await window.crypto.subtle.deriveBits({
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: new Uint8Array()
        }, importedSharedSecret, 256);
        return {
            sharedSecret: btoa(String.fromCharCode(...new Uint8Array(derivedKey)))
        };
    }
    async generateRandomBytes(options) {
        if (typeof (window.crypto) === "undefined") {
            throw this.unavailable("Crypto API not available");
        }
        const randomBytes = new Uint8Array(options.count);
        window.crypto.getRandomValues(randomBytes);
        return {
            bytesBase64: btoa(String.fromCharCode(...randomBytes))
        };
    }
    async encrypt(options) {
        if (typeof (window.crypto) === "undefined") {
            throw this.unavailable("Crypto API not available");
        }
        // IV must be 12 bytes for this AES-GCM
        const randomBytes = await this.generateRandomBytes({
            count: 12
        });
        const ivBytes = Uint8Array.from(atob(randomBytes.bytesBase64), x => x.charCodeAt(0));
        let keyBytes = Uint8Array.from(atob(options.key), x => x.charCodeAt(0));
        const importedKey = await window.crypto.subtle.importKey("raw", keyBytes, {
            "name": "AES-GCM"
        }, false, ["encrypt"]);
        const dataBytes = Uint8Array.from(options.data, x => x.charCodeAt(0));
        const encryptedBytesandTag = await window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: ivBytes,
            tagLength: 128
        }, importedKey, dataBytes);
        // returns data as base64
        // returns IV as this must be sent with the message to be decrypted (iv doesn't have to be secret just random)
        const encryptedBytes = encryptedBytesandTag.slice(0, encryptedBytesandTag.byteLength - 16);
        const tag = encryptedBytesandTag.slice(encryptedBytesandTag.byteLength - 16);
        return {
            encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedBytes))),
            tag: btoa(String.fromCharCode(...new Uint8Array(tag))),
            iv: btoa(String.fromCharCode(...ivBytes))
        };
    }
    async decrypt(options) {
        if (typeof (window.crypto) === "undefined") {
            throw this.unavailable("Crypto API not available");
        }
        const ivBytes = Uint8Array.from(atob(options.iv), x => x.charCodeAt(0));
        let keyBytes = Uint8Array.from(atob(options.key), x => x.charCodeAt(0));
        const importedKey = await window.crypto.subtle.importKey("raw", keyBytes, {
            "name": "AES-GCM"
        }, false, ["decrypt"]);
        const encryptedDataBytes = Uint8Array.from(atob(options.encryptedData), x => x.charCodeAt(0));
        const tagBytes = Uint8Array.from(atob(options.tag), x => x.charCodeAt(0));
        let tagAndBytes = new Uint8Array(encryptedDataBytes.length + tagBytes.length);
        tagAndBytes.set(encryptedDataBytes);
        tagAndBytes.set(tagBytes, encryptedDataBytes.length);
        const unencryptedData = await window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: ivBytes,
            tagLength: 128
        }, importedKey, tagAndBytes);
        return {
            unencryptedData: new TextDecoder().decode(unencryptedData)
        };
    }
    async hash(options) {
        const dataBytes = new TextEncoder().encode(options.data);
        const hashedBytes = await window.crypto.subtle.digest("SHA-512", dataBytes);
        //https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string
        const hashArray = Array.from(new Uint8Array(hashedBytes)); // convert buffer to byte array
        const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
        return {
            hash: hashHex
        };
    }
}
//# sourceMappingURL=web.js.map