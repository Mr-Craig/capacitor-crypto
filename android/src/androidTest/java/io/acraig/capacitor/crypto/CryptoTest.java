package io.acraig.capacitor.crypto;

import static org.junit.Assert.*;

import android.util.Base64;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import androidx.test.ext.junit.runners.AndroidJUnit4;

@RunWith(AndroidJUnit4.class)
public class CryptoTest {

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void generateKeyPair() throws Exception {
        Crypto implementation = new Crypto();

        String[] generatedKeys = implementation.generateKeyPair();

        assertEquals(generatedKeys.length, Crypto.ARRAY_KEY_SIZE);
    }

    @Test
    public void generateRandomBytes() throws Exception {
        Crypto implementation = new Crypto();

        int RANDOM_BYTES = 32;

        String randomBytes = implementation.generateRandomBytes(RANDOM_BYTES);

        byte[] ByteArray = Base64.decode(randomBytes, Base64.DEFAULT);

        assertEquals(ByteArray.length, RANDOM_BYTES);
    }

    @Test
    public void generateSharedSecret() throws Exception {
        Crypto implementation = new Crypto();

        String[] BobKeys = implementation.generateKeyPair();
        String[] AliceKeys = implementation.generateKeyPair();

        String AliceSecret = implementation.generateSharedSecret(BobKeys[Crypto.ARRAY_PUBLIC_KEY], AliceKeys[Crypto.ARRAY_PRIVATE_KEY]);
        String BobSecret = implementation.generateSharedSecret(AliceKeys[Crypto.ARRAY_PUBLIC_KEY], BobKeys[Crypto.ARRAY_PRIVATE_KEY]);

        assertEquals(AliceSecret, BobSecret);
    }

    @Test
    public void testEncryption() throws Exception {
        Crypto implementation = new Crypto();

        String[] BobKeys = implementation.generateKeyPair();
        String[] AliceKeys = implementation.generateKeyPair();

        String AliceSecret = implementation.generateSharedSecret(BobKeys[Crypto.ARRAY_PUBLIC_KEY], AliceKeys[Crypto.ARRAY_PRIVATE_KEY]);
        String BobSecret = implementation.generateSharedSecret(AliceKeys[Crypto.ARRAY_PUBLIC_KEY], BobKeys[Crypto.ARRAY_PRIVATE_KEY]);

        String Text = "Hello, Testing!";

        String[] EncryptedResponse = implementation.encrypt(AliceSecret, Text);
        String DecryptedResponse = implementation.decrypt(BobSecret, EncryptedResponse[Crypto.ENCRYPT_CIPHERTEXT], EncryptedResponse[Crypto.ENCRYPT_TAG], EncryptedResponse[Crypto.ENCRYPT_IV]);

        assertEquals(Text, DecryptedResponse);
    }

    @Test
    public void testWebEncryption() throws Exception {
        Crypto implementation = new Crypto();

        // output from web
        String sharedSecret = "NLSOGZX4BXhx32tG9UGMs9uS9Gwfrb4vkIyxdMQQpXw=";
        String encryptedData = "c9OhmsuPwBTV7uEbEO+D";
        String tag = "fRZ4V/m7P4GSc/WZe2pNnA==";
        String iv = "eAGFKX/vo8AlukxK";

        String DecryptedResponse = implementation.decrypt(sharedSecret, encryptedData, tag, iv);

        assertEquals(DecryptedResponse, "Hello, Testing!");
    }

    @Test
    public void testIosEncryption() throws Exception {
        Crypto implementation = new Crypto();

        // output from ios
        String sharedSecret = "Bu0n6eX7cWq/u7VOWk/UJZDgIx2+hNYzUv1+4BcoMwM=";
        String encryptedData = "v6C9LO4/w1qbk8T/5xpF";
        String tag = "mNLE0ReM+tdj8489FiEAEA==";
        String iv = "2Hlr4zSYKQcjX/Ae";

        String DecryptedResponse = implementation.decrypt(sharedSecret, encryptedData, tag, iv);

        assertEquals(DecryptedResponse, "Hello, Testing!");
    }
}