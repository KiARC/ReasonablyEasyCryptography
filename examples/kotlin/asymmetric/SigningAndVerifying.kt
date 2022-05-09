package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object SigningAndVerifying {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define message
        val message = "Hello World!"
        //Generate a KeyPair
        val keys = RSAHandler.generateKeyPair()
        //Generate signature
        val signature = RSAHandler.sign(message.toByteArray(), keys.private)
        //Verify signature, value will be true if the signature is good and false if it's bad
        val isValid = RSAHandler.verify(message.toByteArray(), signature, keys.public)
    }
}