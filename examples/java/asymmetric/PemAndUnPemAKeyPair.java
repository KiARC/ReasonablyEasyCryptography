package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler;
import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMPair;
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler;

import java.security.KeyPair;

public class PemAndUnPemAKeyPair {
    public static void main(String[] args) {
        //Generate a keypair
        KeyPair keys = RSAEncryptionHandler.generateKeyPair();
        //Generate PEMPair from the KeyPair
        PEMPair pem = PEMHandler.keyPairToPem(keys);
        //Convert PEMPair back to KeyPair
        KeyPair newKeys = PEMHandler.pemPairToKeyPair(pem);
    }
}
