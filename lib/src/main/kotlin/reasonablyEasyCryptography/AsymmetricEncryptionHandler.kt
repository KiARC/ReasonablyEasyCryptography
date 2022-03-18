package reasonablyEasyCryptography

import java.nio.ByteBuffer
import java.security.*
import javax.crypto.Cipher

class AsymmetricEncryptionHandler {
    companion object {
        /**
         * Generates an RSA KeyPair of a given keysize to be used for encryption
         *
         * @author Katherine Rose
         * @param keySize the size in bits of the key to generate
         * @return a new KeyPair
         */
        @JvmStatic
        fun generateKeyPair(keySize: Int = 2048): KeyPair {
            val gen: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
            gen.initialize(keySize)
            return gen.generateKeyPair()
        }

        /**
         * Encrypts data with a given public key
         *
         * Generates a symmetric key, encrypts the data via AES, encrypts the symmetric key using RSA, puts them together and returns them as a ByteArray
         *
         * @author Katherine Rose
         * @param data the data to encrypt
         * @param key the key to use for encryption
         * @return the encrypted data and its encrypted symmetric key
         */
        fun encrypt(data: ByteArray, key: PublicKey): ByteArray {
            val k = SymmetricEncryptionHandler.generateKey(128)
            val encryptedData = SymmetricEncryptionHandler.encrypt(data, k)
            val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
            c.init(Cipher.ENCRYPT_MODE, key)
            val kEnc = c.doFinal(k.encoded)
            val output = ByteBuffer.allocate(kEnc.size + encryptedData.size)
            output.put(kEnc)
            output.put(encryptedData)
            return output.array()
        }

        /**
         * Decrypts data with a given private key
         *
         * Retrieves the symmetric key from the data, decrypts it and then uses it to decrypt the message
         *
         * @author Katherine Rose
         * @param data the data to decrypt
         * @param key the key to use for decryption
         * @return the decrypted data
         */
        fun decrypt(data: ByteArray, key: PrivateKey): ByteArray {
            val c = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING")
            c.init(Cipher.DECRYPT_MODE, key)
            val buffer = ByteBuffer.wrap(data)
            val kB = ByteArray(256)
            buffer.get(kB)
            val enc = ByteArray(buffer.remaining())
            buffer.get(enc)
            val k = SymmetricEncryptionHandler.assembleKey(c.doFinal(kB))
            return SymmetricEncryptionHandler.decrypt(enc, k)
        }

        /**
         * Signs data with a given private key
         *
         * @author Katherine Rose
         * @param data the data to sign
         * @param key the key to sign with
         * @return a signature generated from the data and the key
         */
        fun sign(data: ByteArray, key: PrivateKey): ByteArray {
            val s = Signature.getInstance("SHA256withRSA")
            s.initSign(key)
            s.update(data)
            return s.sign()
        }

        /**
         * Verifies a signature on a piece of data using a public key
         *
         * @author Katherine Rose
         * @param data the data to verify the signature against
         * @param sig the signature to be verified
         * @param key the key to use for verification (i.e. the public counterpart to the private key that created the signature)
         * @return true if the signature is valid, false if not
         */
        fun verify(data: ByteArray, sig: ByteArray, key: PublicKey): Boolean {
            val s = Signature.getInstance("SHA256withRSA")
            s.initVerify(key)
            s.update(data)
            return s.verify(sig)
        }

        /**
         * Encrypts and then signs a piece of data
         *
         * @author Katherine Rose
         * @param data the data to encrypt and sign
         * @param encryptionKey the key to use for encryption
         * @param signingKey the key to use for signing
         * @return a Pair, in which the first ByteArray is the encrypted data and the second is the signature
         */
        fun encryptAndSign(
            data: ByteArray,
            encryptionKey: PublicKey,
            signingKey: PrivateKey
        ): Pair<ByteArray, ByteArray> {
            val enc = encrypt(data, encryptionKey)
            val sig = sign(enc, signingKey)
            return Pair(enc, sig)
        }

        /**
         * Verifies and decrypts data
         *
         * Verifies the data with the signature and verification key, then if the signature is valid, decrypts it with the decryption key
         * @author Katherine Rose
         * @param data the data to decrypt
         * @param sig the signature to verify
         * @param decryptionKey the key to use for decryption
         * @param verificationKey the key to use for verification of the signature
         * @param exceptionOnFailure whether to throw an exception if the signature is invalid or not, if false it will return null instead
         * @return the decrypted data, or null if the signature is invalid and exceptionOnFailure is false
         * @throws SecurityException if the signature is invalid and exceptionOnFailure is true
         */
        @JvmStatic
        fun decryptAndVerify(
            data: ByteArray,
            sig: ByteArray,
            decryptionKey: PrivateKey,
            verificationKey: PublicKey,
            exceptionOnFailure: Boolean = true
        ): ByteArray? {
            return if (verify(data, sig, verificationKey)) decrypt(data, decryptionKey)
            else if (exceptionOnFailure) throw SecurityException("Signature verification failed.")
            else null
        }
    }
}