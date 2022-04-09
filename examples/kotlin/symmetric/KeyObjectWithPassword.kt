package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler

object KeyObjectWithPassword {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Create a SecretKey using a password
        val key = AESEncryptionHandler.stringToKey("password")
        //Encrypt the plaintext with it
        val ciphertext = AESEncryptionHandler.encrypt(plaintext.toByteArray(), key)
        //Decrypt it with the same key
        val decrypted = AESEncryptionHandler.decrypt(ciphertext, key)
        //And we're done
        val deciphered = String(decrypted)
    }
}