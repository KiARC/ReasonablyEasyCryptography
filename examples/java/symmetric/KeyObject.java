package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler;

import javax.crypto.SecretKey;

public class KeyObject {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Create a SecretKey. You can also specify a keysize but the default (256) is fine.
        SecretKey key = AESHandler.generateKey();
        //Encrypt the plaintext with it
        byte[] ciphertext = AESHandler.encrypt(plaintext.getBytes(), key);
        //Decrypt it with the same key
        String decrypted = new String(AESHandler.decrypt(ciphertext, key));
        //Et voila!
    }
}
