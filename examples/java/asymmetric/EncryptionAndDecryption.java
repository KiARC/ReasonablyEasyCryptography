package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.security.KeyPair;

public class EncryptionAndDecryption {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate a KeyPair
        KeyPair keys = RSAHandler.generateKeyPair();
        //Encrypt data
        byte[] encrypted = RSAHandler.encrypt(plaintext.getBytes(), keys.getPublic());
        //Decrypt data
        String decrypted = new String(RSAHandler.decrypt(encrypted, keys.getPrivate()));
    }
}
