package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler

object SigningAndVerifying {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define message
        val message = "Hello World!"
        //Generate a KeyPair
        val keys = RSAEncryptionHandler.generateKeyPair()
        //Generate signature
        val signature = RSAEncryptionHandler.sign(message.toByteArray(), keys.private)
        //Verify signature, value will be true if the signature is good and false if it's bad
        val isValid = RSAEncryptionHandler.verify(message.toByteArray(), signature, keys.public)
    }
}