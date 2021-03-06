package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler

object KeyObject {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Create a SecretKey. You can also specify a keysize but the default (256) is fine.
        val key = AESHandler.generateKey()
        //Encrypt the plaintext with it
        val ciphertext = AESHandler.encrypt(plaintext.toByteArray(), key)
        //Decrypt it with the same key
        val decrypted = String(AESHandler.decrypt(ciphertext, key))
    }
}