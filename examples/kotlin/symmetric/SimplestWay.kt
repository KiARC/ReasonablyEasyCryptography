package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler

object SimplestWay {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Encrypt it with a password
        val ciphertext = AESHandler.encrypt(plaintext.toByteArray(), "password")
        //Decrypt it with the same password
        val decrypted = String(AESHandler.decrypt(ciphertext, "password"))
    }
}