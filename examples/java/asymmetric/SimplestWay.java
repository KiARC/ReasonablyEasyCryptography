package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler;
import com.katiearose.reasonablyEasyCryptography.asymmetric.SignedDataContainer;

import java.security.KeyPair;

public class SimplestWay {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Generate a KeyPair, you can specify a keysize but the default (2048) is fine
        KeyPair keys = RSAHandler.generateKeyPair();
        //Encrypt and sign plaintext using keys. Usually you'd use someone else's
        //public key for encryption and then send the encrypted data to them but
        //in this example I'll just use one keypair for convenience
        SignedDataContainer sdc = RSAHandler.encryptAndSign(plaintext.getBytes(), keys.getPublic(), keys.getPrivate());
        //Decrypt and verify ciphertext and signature in the SignedDataContainer.
        //This method wil throw an exception if the signature is bad unless you
        //explicitly tell it not to by setting the exceptionOnFailure flag to false,
        //in which case it will just return null. If you don't actually care about the
        //signature, just decrypt it outright, don't bother checking unless the validity matters.
        //You can also pass the data and the signature separately but a SignedDataContainer makes life easier.
        String decrypted = new String(RSAHandler.decryptAndVerify(sdc, keys.getPrivate(), keys.getPublic()));
    }
}
