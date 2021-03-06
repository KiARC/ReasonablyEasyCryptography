package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object PemAndUnPemAKeyPair {
    @JvmStatic
    fun main(args: Array<String>) {
        //Generate a keypair
        val keys = RSAHandler.generateKeyPair()
        //Generate PEMPair from the KeyPair
        val pem = PEMHandler.keyPairToPem(keys)
        //Convert PEMPair back to KeyPair
        val newKeys = PEMHandler.pemPairToKeyPair(pem)
    }
}