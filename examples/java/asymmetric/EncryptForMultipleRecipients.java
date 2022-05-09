package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;

public class EncryptForMultipleRecipients {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate the first recipient KeyPair
        KeyPair recipient1 = RSAHandler.generateKeyPair();
        //Generate the second recipient KeyPair
        KeyPair recipient2 = RSAHandler.generateKeyPair();
        //Create a List for the public keys
        ArrayList<PublicKey> keys = new ArrayList<>();
        //Add the keys to the list
        keys.add(recipient1.getPublic());
        keys.add(recipient2.getPublic());
        //Encrypt data
        byte[] encrypted = RSAHandler.encrypt(plaintext.getBytes(), keys);
        //Decrypt data for recipient 1
        String decrypted1 = new String(RSAHandler.decrypt(encrypted, recipient1.getPrivate()));
        //Decrypt data for recipient 2
        String decrypted2 = new String(RSAHandler.decrypt(encrypted, recipient2.getPrivate()));
        //plaintext == decrypted1 == decrypted2, and you only have to send or store one message that
        //both keys can decrypt
    }
}
