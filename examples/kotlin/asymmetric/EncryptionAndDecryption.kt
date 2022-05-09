package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object EncryptionAndDecryption {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate a KeyPair
        val keys = RSAHandler.generateKeyPair()
        //Encrypt data
        val encrypted = RSAHandler.encrypt(plaintext.toByteArray(), keys.public)
        //Decrypt data
        val decrypted = String(RSAHandler.decrypt(encrypted, keys.private))
    }
}