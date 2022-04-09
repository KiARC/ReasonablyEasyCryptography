package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler;

import java.security.KeyPair;

public class EncryptionAndDecryption {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate a KeyPair
        KeyPair keys = RSAEncryptionHandler.generateKeyPair();
        //Encrypt data
        byte[] encrypted = RSAEncryptionHandler.encrypt(plaintext.getBytes(), keys.getPublic());
        //Decrypt data
        byte[] decrypted = RSAEncryptionHandler.decrypt(encrypted, keys.getPrivate());
        //And here's your string back
        String deciphered = new String(decrypted);
    }
}
