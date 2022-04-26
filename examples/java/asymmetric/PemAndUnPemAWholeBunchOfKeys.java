package java.asymmetric;

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler;
import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMObject;
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class PemAndUnPemAWholeBunchOfKeys {
    public static void main(String[] args) {
        //This code doesn't pertain as much to the actual example, but I need a
        //list of keys and decided this would be a good way to do it
        ArrayList<Key> keys = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            KeyPair k = RSAEncryptionHandler.generateKeyPair();
            keys.add(k.getPrivate());
            keys.add(k.getPublic());
        }
        //Now that we have a list of 20 keys (10 private and 10 public) we can get started
        //Define a StringBuilder to add the keys to
        StringBuilder builder = new StringBuilder();
        //First, loop over the keys and convert them all to PEMs, then put those PEMs into our StringBuilder
        for (Key key : keys) {
            builder.append(PEMHandler.keyToPem(key)).append(System.lineSeparator());
        }
        //Now we convert the builder to a string, like what you might read from a file full of keys
        String PEMList = builder.toString();
        //Initialize the List where we'll store the unpemed keys
        ArrayList<Key> keysUnpemed = new ArrayList<>();
        //Use the handy parsePemStream function to parse all of the PEMs in the String in one call
        List<PEMObject> p = PEMHandler.parsePemStream(new ByteArrayInputStream(PEMList.getBytes()));
        //Loop over the new PEMObjects and unpem them
        for (int i = 0; i < keys.size(); i++) {
            PEMObject it = p.get(i);
            keysUnpemed.add(PEMHandler.pemToKey(it));
        }
        //keysUnpemed now contains all the same keys as keys
    }
}
