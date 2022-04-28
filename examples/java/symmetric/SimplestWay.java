package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler;

public class SimplestWay {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Encrypt it with a password
        byte[] ciphertext = AESEncryptionHandler.encrypt(plaintext.getBytes(), "password");
        //Decrypt it with the same password
        String decrypted = new String(AESEncryptionHandler.decrypt(ciphertext, "password"));
    }
}
