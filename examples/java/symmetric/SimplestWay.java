package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler;

public class SimplestWay {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Encrypt it with a password
        byte[] ciphertext = AESEncryptionHandler.encrypt(plaintext.getBytes(), "password");
        //Decrypt it with the same password
        byte[] decrypted = AESEncryptionHandler.decrypt(ciphertext, "password");
        //Convert it back to a string, and you're back where you started
        String deciphered = new String(decrypted);
    }
}
