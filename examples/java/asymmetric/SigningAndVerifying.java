package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler;

import java.security.KeyPair;

public class SigningAndVerifying {
    public static void main(String[] args) {
        //Define message
        String message = "Hello World!";
        //Generate a KeyPair
        KeyPair keys = RSAEncryptionHandler.generateKeyPair();
        //Generate signature
        byte[] signature = RSAEncryptionHandler.sign(message.getBytes(), keys.getPrivate());
        //Verify signature, value will be true if the signature is good and false if it's bad
        boolean isValid = RSAEncryptionHandler.verify(message.getBytes(), signature, keys.getPublic());
    }
}
