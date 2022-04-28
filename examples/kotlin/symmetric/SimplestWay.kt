package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler

object SimplestWay {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Encrypt it with a password
        val ciphertext = AESEncryptionHandler.encrypt(plaintext.toByteArray(), "password")
        //Decrypt it with the same password
        val decrypted = String(AESEncryptionHandler.decrypt(ciphertext, "password"))
    }
}