package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler;

import javax.crypto.SecretKey;

public class KeyObject {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Create a SecretKey. You can also specify a keysize but the default (256) is fine.
        SecretKey key = AESEncryptionHandler.generateKey();
        //Encrypt the plaintext with it
        byte[] ciphertext = AESEncryptionHandler.encrypt(plaintext.getBytes(), key);
        //Decrypt it with the same key
        byte[] decrypted = AESEncryptionHandler.decrypt(ciphertext, key);
        //Et voila!
        String deciphered = new String(decrypted);
    }
}
