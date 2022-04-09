package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler;

import javax.crypto.SecretKey;

public class SerializingAndDeserializingAKey {
    public static void main(String[] args) {
        //Create your key however you want, I'll use REC but this works with any javax.crypto.SecretKey
        SecretKey key1 = AESEncryptionHandler.generateKey();
        //Get the encoded form of the key
        byte[] encoded = key1.getEncoded();
        //The key is now serialized, and REC makes it easy to deserialize it
        SecretKey key2 = AESEncryptionHandler.assembleKey(encoded);
        //key2 is able to decrypt things encrypted with key1 and vice versa, because they're the same key.
    }
}
