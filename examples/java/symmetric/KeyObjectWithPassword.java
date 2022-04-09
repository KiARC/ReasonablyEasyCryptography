package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler;

import javax.crypto.SecretKey;

public class KeyObjectWithPassword {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Create a SecretKey using a password
        SecretKey key = AESEncryptionHandler.stringToKey("password");
        //Encrypt the plaintext with it
        byte[] ciphertext = AESEncryptionHandler.encrypt(plaintext.getBytes(), key);
        //Decrypt it with the same key
        byte[] decrypted = AESEncryptionHandler.decrypt(ciphertext, key);
        //And we're done
        String deciphered = new String(decrypted);
    }
}
