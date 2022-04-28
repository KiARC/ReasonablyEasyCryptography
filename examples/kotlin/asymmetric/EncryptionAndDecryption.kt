package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler

object EncryptionAndDecryption {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate a KeyPair
        val keys = RSAEncryptionHandler.generateKeyPair()
        //Encrypt data
        val encrypted = RSAEncryptionHandler.encrypt(plaintext.toByteArray(), keys.public)
        //Decrypt data
        val decrypted = RSAEncryptionHandler.decrypt(encrypted, keys.private)
        //And here's your string back
        val deciphered = String(decrypted)
    }
}