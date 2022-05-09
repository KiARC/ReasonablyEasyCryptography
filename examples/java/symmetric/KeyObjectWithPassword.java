package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler;

import javax.crypto.SecretKey;

public class KeyObjectWithPassword {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Create a SecretKey using a password
        SecretKey key = AESHandler.stringToKey("password");
        //Encrypt the plaintext with it
        byte[] ciphertext = AESHandler.encrypt(plaintext.getBytes(), key);
        //Decrypt it with the same key
        String decrypted = new String(AESHandler.decrypt(ciphertext, key));
    }
}
