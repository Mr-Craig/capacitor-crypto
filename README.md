# capacitor-crypto

Native crypto functions for ECDH key exchange and AES encryption/decryption.

## Install

```bash
npm install capacitor-crypto
npx cap sync
```

## API

<docgen-index>

* [`echo(...)`](#echo)
* [`generateKeyPair()`](#generatekeypair)
* [`generateSharedSecret(...)`](#generatesharedsecret)
* [`generateRandomBytes(...)`](#generaterandombytes)
* [`encrypt(...)`](#encrypt)
* [`decrypt(...)`](#decrypt)
* [`hash(...)`](#hash)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### echo(...)

```typescript
echo(options: { value: string; }) => Promise<{ value: string; }>
```

| Param         | Type                            |
| ------------- | ------------------------------- |
| **`options`** | <code>{ value: string; }</code> |

**Returns:** <code>Promise&lt;{ value: string; }&gt;</code>

--------------------


### generateKeyPair()

```typescript
generateKeyPair() => Promise<{ publicKey: string; privateKey: string; }>
```

**Returns:** <code>Promise&lt;{ publicKey: string; privateKey: string; }&gt;</code>

--------------------


### generateSharedSecret(...)

```typescript
generateSharedSecret(options: { privateKey: string; publicKey: string; salt: string; }) => Promise<{ sharedSecret: string; }>
```

| Param         | Type                                                                  |
| ------------- | --------------------------------------------------------------------- |
| **`options`** | <code>{ privateKey: string; publicKey: string; salt: string; }</code> |

**Returns:** <code>Promise&lt;{ sharedSecret: string; }&gt;</code>

--------------------


### generateRandomBytes(...)

```typescript
generateRandomBytes(options: { count: number; }) => Promise<{ bytesBase64: string; }>
```

| Param         | Type                            |
| ------------- | ------------------------------- |
| **`options`** | <code>{ count: number; }</code> |

**Returns:** <code>Promise&lt;{ bytesBase64: string; }&gt;</code>

--------------------


### encrypt(...)

```typescript
encrypt(options: { key: string; data: string; }) => Promise<{ encryptedData: string; tag: string; iv: string; }>
```

| Param         | Type                                        |
| ------------- | ------------------------------------------- |
| **`options`** | <code>{ key: string; data: string; }</code> |

**Returns:** <code>Promise&lt;{ encryptedData: string; tag: string; iv: string; }&gt;</code>

--------------------


### decrypt(...)

```typescript
decrypt(options: { key: string; encryptedData: string; tag: string; iv: string; }) => Promise<{ unencryptedData: string; }>
```

| Param         | Type                                                                          |
| ------------- | ----------------------------------------------------------------------------- |
| **`options`** | <code>{ key: string; encryptedData: string; tag: string; iv: string; }</code> |

**Returns:** <code>Promise&lt;{ unencryptedData: string; }&gt;</code>

--------------------


### hash(...)

```typescript
hash(options: { data: string; }) => Promise<{ hash: string; }>
```

| Param         | Type                           |
| ------------- | ------------------------------ |
| **`options`** | <code>{ data: string; }</code> |

**Returns:** <code>Promise&lt;{ hash: string; }&gt;</code>

--------------------

</docgen-api>
