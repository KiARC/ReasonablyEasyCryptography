package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;

import java.security.KeyPair;

public class SigningAndVerifying {
    public static void main(String[] args) {
        //Define message
        String message = "Hello World!";
        //Generate a KeyPair
        KeyPair keys = RSAHandler.generateKeyPair();
        //Generate signature
        byte[] signature = RSAHandler.sign(message.getBytes(), keys.getPrivate());
        //Verify signature, value will be true if the signature is good and false if it's bad
        boolean isValid = RSAHandler.verify(message.getBytes(), signature, keys.getPublic());
    }
}
