import { WebPlugin } from '@capacitor/core';

import type { CryptoPlugin } from './definitions';

export class CryptoWeb extends WebPlugin implements CryptoPlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
  
  async generateKeyPair(): Promise<{ publicKey: string; privateKey: string; }> {
    if(typeof(window.crypto.subtle) === "undefined") {
      throw this.unavailable("Subtle API not available");
    }

    if(!window.isSecureContext) {
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
    }
  }

  async generateSharedSecret(options: { privateKey: string; publicKey: string; salt: string }): Promise<{ sharedSecret: string; }> {
    if(typeof(window.crypto.subtle) === "undefined") {
      throw this.unavailable("Subtle API not available");
    }

    if(!window.isSecureContext) {
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
    }
  }

  async generateRandomBytes(options: { count: number; }): Promise<{ bytesBase64: string}> {
    if(typeof(window.crypto) === "undefined") {
      throw this.unavailable("Crypto API not available");
    }

    const randomBytes = new Uint8Array(options.count);
    window.crypto.getRandomValues(randomBytes);

    return {
      bytesBase64: btoa(String.fromCharCode(...randomBytes))
    };
  }

  async encrypt(options: { key: string; data: string; }): Promise<{ encryptedData: string; tag: string; iv: string; }> {
    if(typeof(window.crypto) === "undefined") {
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

    const encryptedBytes = encryptedBytesandTag.slice(0, encryptedBytesandTag.byteLength-16);
    const tag = encryptedBytesandTag.slice(encryptedBytesandTag.byteLength-16);
    return {
      encryptedData: btoa(String.fromCharCode(...new Uint8Array(encryptedBytes))),
      tag: btoa(String.fromCharCode(...new Uint8Array(tag))),
      iv: btoa(String.fromCharCode(...ivBytes))
    }
  }
  async decrypt(options: { key: string; encryptedData: string; tag: string; iv: string; }): Promise<{ unencryptedData: string; }> {
    if(typeof(window.crypto) === "undefined") {
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
    }
  }
}