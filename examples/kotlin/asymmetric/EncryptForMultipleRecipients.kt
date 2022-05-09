package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.generateKeyPair
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.encrypt
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler.decrypt
import java.security.PublicKey
import java.util.ArrayList

object EncryptForMultipleRecipients {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate the first recipient KeyPair
        val recipient1 = generateKeyPair()
        //Generate the second recipient KeyPair
        val recipient2 = generateKeyPair()
        //Create a List for the public keys
        val keys = ArrayList<PublicKey>()
        //Add the keys to the list
        keys.add(recipient1.public)
        keys.add(recipient2.public)
        //Encrypt data
        val encrypted = encrypt(plaintext.toByteArray(), keys)
        //Decrypt data for recipient 1
        val decrypted1 = String(decrypt(encrypted, recipient1.private))
        //Decrypt data for recipient 2
        val decrypted2 = String(decrypt(encrypted, recipient2.private))
        //plaintext == decrypted1 == decrypted2, and you only have to send or store one message that
        //both keys can decrypt
    }
}