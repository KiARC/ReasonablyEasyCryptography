package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler

object KeyObject {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Create a SecretKey. You can also specify a keysize but the default (256) is fine.
        val key = AESEncryptionHandler.generateKey()
        //Encrypt the plaintext with it
        val ciphertext = AESEncryptionHandler.encrypt(plaintext.toByteArray(), key)
        //Decrypt it with the same key
        val decrypted = AESEncryptionHandler.decrypt(ciphertext, key)
        //Et voila!
        val deciphered = String(decrypted)
    }
}