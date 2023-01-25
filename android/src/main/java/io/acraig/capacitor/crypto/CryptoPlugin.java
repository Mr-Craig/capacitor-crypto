package io.acraig.capacitor.crypto;

import android.os.Build;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

@CapacitorPlugin(name = "Crypto")
public class CryptoPlugin extends Plugin {

    private Crypto implementation = new Crypto();

    @PluginMethod
    public void echo(PluginCall call) {
        String value = call.getString("value");

        JSObject ret = new JSObject();
        ret.put("value", implementation.echo(value));
        call.resolve(ret);
    }

    @PluginMethod
    public void generateSharedSecret(PluginCall call)
    {
        String privateKey = call.getString("privateKey");
        String publicKey = call.getString("publicKey");

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            call.unavailable("Android Version too old!");
            return;
        }

        try
        {
            String sharedSecret = implementation.generateSharedSecret(publicKey, privateKey);

            JSObject ReturnValue = new JSObject();
            ReturnValue.put("sharedSecret", sharedSecret);

            call.resolve(ReturnValue);
        } catch (Exception e) {
            call.reject("Unable to generate Shared Secret", e);
        }
    }

    @PluginMethod
    public void generateRandomBytes(PluginCall call)
    {
        int byteCount = call.getInt("count");

        try
        {
            String randomBytesBase64 = implementation.generateRandomBytes(byteCount);

            JSObject ReturnValue = new JSObject();
            ReturnValue.put("bytesBase64", randomBytesBase64);

            call.resolve(ReturnValue);
        } catch (Exception e) {
            call.reject("Unable to generate random bytes", e);
        }
    }
    @PluginMethod
    public void generateKeyPair(PluginCall call)
    {
        JSObject ret = new JSObject();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            call.unavailable("Android Version too old!");
            return;
        }

        try {
            String[] GeneratedKeys = implementation.generateKeyPair();

            JSObject ReturnValue = new JSObject();

            ReturnValue.put("privateKey", GeneratedKeys[Crypto.ARRAY_PRIVATE_KEY]);
            ReturnValue.put("publicKey", GeneratedKeys[Crypto.ARRAY_PUBLIC_KEY]);

            call.resolve(ReturnValue);
        } catch (Exception e) {
            call.reject("Unable to generate KeyPair: "+e.getMessage());
        }
    }

    @PluginMethod
    public void encrypt(PluginCall call) {
        JSObject ret = new JSObject();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            call.unavailable("Android Version too old!");
            return;
        }

        String key = call.getString("key");
        String data = call.getString("data");
        try {
            String[] encryptRes = implementation.encrypt(key, data);

            ret.put("encryptedData", encryptRes[Crypto.ENCRYPT_CIPHERTEXT]);
            ret.put("tag", encryptRes[Crypto.ENCRYPT_TAG]);
            ret.put("iv", encryptRes[Crypto.ENCRYPT_IV]);

            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Failed to encrypt", e);
        }
    }

    @PluginMethod
    public void decrypt(PluginCall call) {
        JSObject ret = new JSObject();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            call.unavailable("Android Version too old!");
            return;
        }

        String key = call.getString("key");
        String encryptedData = call.getString("encryptedData");
        String tag = call.getString("tag");
        String iv = call.getString("iv");
        
        try {
            String decryptedData = implementation.decrypt(key, encryptedData, tag, iv);
            ret.put("unencryptedData", decryptedData);
            call.resolve(ret);
        } catch (Exception e) {
            call.reject("Failed to encrypt", e);
        }
    }
}
