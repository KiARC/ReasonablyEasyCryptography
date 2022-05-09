package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler

object SerializingAndDeserializingAKey {
    @JvmStatic
    fun main(args: Array<String>) {
        //Create your key however you want, I'll use REC but this works with any javax.crypto.SecretKey
        val key1 = AESHandler.generateKey()
        //Get the encoded form of the key
        val encoded = key1.encoded
        //The key is now serialized, and REC makes it easy to deserialize it
        val key2 = AESHandler.assembleKey(encoded)
        //key2 is able to decrypt things encrypted with key1 and vice versa, because they're the same key.
    }
}