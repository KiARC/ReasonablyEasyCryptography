package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler

object KeyObjectWithPassword {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Create a SecretKey using a password
        val key = AESHandler.stringToKey("password")
        //Encrypt the plaintext with it
        val ciphertext = AESHandler.encrypt(plaintext.toByteArray(), key)
        //Decrypt it with the same key
        val decrypted = String(AESHandler.decrypt(ciphertext, key))
    }
}