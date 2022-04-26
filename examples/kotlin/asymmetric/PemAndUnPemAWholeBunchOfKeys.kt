package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler
import java.io.ByteArrayInputStream
import java.security.Key

object PemAndUnPemAWholeBunchOfKeys {
    @JvmStatic
    fun main(args: Array<String>) {
        //This code doesn't pertain as much to the actual example, but I need a
        //list of keys and decided this would be a good way to do it
        val keys = ArrayList<Key>()
        for (i in 1..10 ) {
            val k = RSAEncryptionHandler.generateKeyPair()
            keys.add(k.private)
            keys.add(k.public)
        }
        //Now that we have a list of 20 keys (10 private and 10 public) we can get started
        //Define a StringBuilder to add the keys to
        val builder = StringBuilder()
        //First, loop over the keys and convert them all to PEMs, then put those PEMs into our StringBuilder
        for (key in keys) {
            builder.append(PEMHandler.keyToPem(key)).append(System.lineSeparator())
        }
        //Now we convert the builder to a string, like what you might read from a file full of keys
        val PEMList = builder.toString()
        //Initialize the List where we'll store the unpemed keys
        val keysUnpemed = ArrayList<Key>()
        //Use the handy parsePemStream function to parse all of the PEMs in the String in one call
        val p = PEMHandler.parsePemStream(ByteArrayInputStream(PEMList.toByteArray()))
        //Loop over the new PEMObjects and unpem them
        for (i in keys.indices) {
            val it = p[i]
            keysUnpemed.add(PEMHandler.pemToKey(it))
        }
        //keysUnpemed now contains all the same keys as keys
    }
}