package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler

object SerializingAndDeserializingAKey {
    @JvmStatic
    fun main(args: Array<String>) {
        //Create your key however you want, I'll use REC but this works with any javax.crypto.SecretKey
        val key1 = AESEncryptionHandler.generateKey()
        //Get the encoded form of the key
        val encoded = key1.encoded
        //The key is now serialized, and REC makes it easy to deserialize it
        val key2 = AESEncryptionHandler.assembleKey(encoded)
        //key2 is able to decrypt things encrypted with key1 and vice versa, because they're the same key.
    }
}