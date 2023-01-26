package io.acraig.capacitor.crypto;

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.crypto.tink.*;
import com.google.crypto.tink.subtle.Hkdf;

public class Crypto {
    public String echo(String value) {
        Log.i("Echo", value);

        return value;
    }

    public static int ARRAY_PUBLIC_KEY = 1;
    public static int ARRAY_PRIVATE_KEY = 0;
    public static int ARRAY_KEY_SIZE = 2;

    public static int ENCRYPT_ARRAY_SIZE = 3;
    public static int ENCRYPT_CIPHERTEXT = 0;
    public static int ENCRYPT_TAG = 1;
    public static int ENCRYPT_IV = 2;

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String[] generateKeyPair() throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));

        KeyPair generatedKeyPair = keyPairGenerator.generateKeyPair();

        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(generatedKeyPair.getPrivate().getEncoded());

        String[] Ret = new String[ARRAY_KEY_SIZE];

        Ret[ARRAY_PUBLIC_KEY] = Base64.encodeToString(generatedKeyPair.getPublic().getEncoded(), Base64.NO_WRAP);
        Ret[ARRAY_PRIVATE_KEY] = Base64.encodeToString(generatedKeyPair.getPrivate().getEncoded(), Base64.NO_WRAP);

        return Ret;
    }

    public String generateRandomBytes(int count) throws Exception
    {
        SecureRandom Random = new SecureRandom();

        byte randBytes[] = new byte[count];

        Random.nextBytes(randBytes);

        String ReturnValue = Base64.encodeToString(randBytes, Base64.NO_WRAP);

        return ReturnValue;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public String generateSharedSecret(String publicKeyBase64, String privateKeyBase64, String saltBase64) throws Exception
    {
        byte[] publicKeyBuffer = Base64.decode(publicKeyBase64, Base64.NO_WRAP);
        byte[] privateKeyBuffer = Base64.decode(privateKeyBase64, Base64.NO_WRAP);

        KeyFactory keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC);

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBuffer));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBuffer));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] salt = Base64.decode(saltBase64, Base64.NO_WRAP);
        byte[] info = {};

        byte[] finalKey = Hkdf.computeHkdf("HMACSHA256", sharedSecret, salt, info, 32);

        String keyBase64 = Base64.encodeToString(finalKey, Base64.NO_WRAP);

        return keyBase64;
    }

    public String decrypt(String key, String cipherText, String tag, String iv) throws Exception
    {
        int tagSize = 128;

        byte[] keyBytes = Base64.decode(key, Base64.NO_WRAP);
        byte[] ctBytes = Base64.decode(cipherText, Base64.NO_WRAP);
        byte[] tagBytes = Base64.decode(tag, Base64.NO_WRAP);
        byte[] ivBytes = Base64.decode(iv, Base64.NO_WRAP);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(tagSize, ivBytes);

        byte[] ctAndTag = new byte[ctBytes.length+tagBytes.length];
        System.arraycopy( ctBytes, 0, ctAndTag, 0, ctBytes.length);
        System.arraycopy( tagBytes, 0, ctAndTag, ctBytes.length, tagBytes.length);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] unencryptedBytes = cipher.doFinal(ctAndTag);

        return new String(unencryptedBytes, StandardCharsets.UTF_8);
    }
    public String[] encrypt(String key, String data) throws Exception {
        int tagSize = 128;

        byte[] keyBytes = Base64.decode(key, Base64.NO_WRAP);
        byte[] unencryptedBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] iv = Base64.decode(generateRandomBytes(12), Base64.NO_WRAP);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(tagSize, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] encryptedBytesAndTag = cipher.doFinal(unencryptedBytes);

        String encryptedBAT = Base64.encodeToString(encryptedBytesAndTag, Base64.NO_WRAP);

        int ctSize = encryptedBytesAndTag.length - tagSize / Byte.SIZE;

        byte[] ct = Arrays.copyOfRange(encryptedBytesAndTag, 0, ctSize);
        byte[] tag = Arrays.copyOfRange(encryptedBytesAndTag, ctSize, encryptedBytesAndTag.length);

        String[] ret = new String[ENCRYPT_ARRAY_SIZE];

        ret[ENCRYPT_CIPHERTEXT] = Base64.encodeToString(ct, Base64.NO_WRAP);
        ret[ENCRYPT_TAG] = Base64.encodeToString(tag, Base64.NO_WRAP);
        ret[ENCRYPT_IV] = Base64.encodeToString(iv, Base64.NO_WRAP);

        return ret;
    }
}
