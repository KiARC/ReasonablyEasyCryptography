package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler;
import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMObject;
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler;

import java.security.PrivateKey;

public class PemAndUnPemAKey {
    public static void main(String[] args) {
        //Generate a key, I'll use the private key from an RSA KeyPair generated by REC
        PrivateKey key = RSAEncryptionHandler.generateKeyPair().getPrivate();
        //Generate PEM for the key
        PEMObject pem = PEMHandler.keyToPem(key);
        //Convert PEM back to key. You have to cast it to the right type, either a PublicKey or a PrivateKey
        PrivateKey newKey = (PrivateKey) PEMHandler.pemToKey(pem);
    }
}
