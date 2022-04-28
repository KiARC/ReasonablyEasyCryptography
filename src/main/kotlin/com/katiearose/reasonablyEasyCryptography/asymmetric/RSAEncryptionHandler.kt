package com.katiearose.reasonablyEasyCryptography.asymmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler
import java.nio.ByteBuffer
import java.security.*
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKey

object RSAEncryptionHandler {
    /**
     * Generates an RSA KeyPair of a given keysize to be used for encryption
     *
     * @author Katherine Rose
     * @param keySize the size in bits of the key to generate
     * @return a new KeyPair
     */
    @JvmOverloads
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
    @JvmStatic
    fun encrypt(data: ByteArray, key: PublicKey): ByteArray {
        val k = AESEncryptionHandler.generateKey(128)
        val encryptedData = AESEncryptionHandler.encrypt(data, k)
        val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
        c.init(Cipher.ENCRYPT_MODE, key)
        val kEnc = c.doFinal(k.encoded)
        val output = ByteBuffer.allocate(kEnc.size + encryptedData.size + 1)
        output.put(0)
        output.put(kEnc)
        output.put(encryptedData)
        return output.array()
    }

    /**
     * Encrypts data with a given list of up to 256 public keys
     *
     * The encrypted data can be decrypted by the private counterpart to any of the keys in the list
     *
     * The limit of 256 is imposed by the fact that I am using a single byte to tell the decryptor how many recipients were specified. It should be enough for most use cases.
     *
     * @author Katherine Rose
     * @param data the data to encrypt
     * @param keys the keys to use for encryption
     * @return the encrypted data and its encrypted symmetric keys
     */
    @JvmStatic
    fun encrypt(data: ByteArray, keys: List<PublicKey>): ByteArray {
        if (keys.size > 256) {
            throw RuntimeException("More than 256 recipients specified at once")
        }
        val encryptedSecrets = ArrayList<ByteArray>(keys.size)
        val k = AESEncryptionHandler.generateKey(128)
        val encryptedData = AESEncryptionHandler.encrypt(data, k)
        for (key in keys) {
            val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
            c.init(Cipher.ENCRYPT_MODE, key)
            encryptedSecrets.add(c.doFinal(k.encoded))
        }
        var totalSize = 0
        for (s in encryptedSecrets) totalSize += s.size
        val output = ByteBuffer.allocate(totalSize + encryptedData.size + 1)
        output.put(((keys.size - 1).toUByte()).toByte()) //Janky math to hopefully make this work
        for (s in encryptedSecrets) output.put(s)
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
    @JvmStatic
    fun decrypt(data: ByteArray, key: PrivateKey): ByteArray {
        val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
        c.init(Cipher.DECRYPT_MODE, key)
        val buffer = ByteBuffer.wrap(data)
        val rbyte = ByteArray(1)
        buffer.get(rbyte)
        val recipientCount = rbyte[0].toUByte()
        val kbs = ArrayDeque<ByteArray>(recipientCount.toInt())
        for (i in 0 until recipientCount.toInt() + 1) {
            val kB = ByteArray(256)
            buffer.get(kB)
            kbs.addFirst(kB)
        }
        var foundKey = false
        var k: SecretKey? = null
        while (!foundKey) {
            try {
                k = AESEncryptionHandler.assembleKey(c.doFinal(kbs.removeFirst()))
                foundKey = true
            } catch (_: BadPaddingException) { /*Ignore that, it just means that wasn't the right one*/
            }
        }
        if (k == null) {
            throw SecurityException("Could not successfully decrypt a key, was this message encrypted for this keypair?")
        }
        val enc = ByteArray(buffer.remaining())
        buffer.get(enc)
        return AESEncryptionHandler.decrypt(enc, k)
    }

    /**
     * Decrypts data with a given private key
     *
     * Retrieves the symmetric key from the data, decrypts it and then uses it to decrypt the message
     *
     * Legacy method from before REC supported multiple recipients, which came with an extra byte at the beginning of the messages
     *
     * @author Katherine Rose
     * @param data the data to decrypt
     * @param key the key to use for decryption

     * @return the decrypted data
     */
    @JvmStatic
    @Deprecated(
        "Only for use on messages encrypted with older versions of REC",
        ReplaceWith("decrypt()"),
        DeprecationLevel.WARNING
    )
    fun legacyDecrypt(data: ByteArray, key: PrivateKey): ByteArray {
        val c = Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
        c.init(Cipher.DECRYPT_MODE, key)
        val buffer = ByteBuffer.wrap(data)
        val kB = ByteArray(256)
        buffer.get(kB)
        val enc = ByteArray(buffer.remaining())
        buffer.get(enc)
        val k = AESEncryptionHandler.assembleKey(c.doFinal(kB))
        return AESEncryptionHandler.decrypt(enc, k)
    }

    /**
     * Signs data with a given private key
     *
     * @author Katherine Rose
     * @param data the data to sign
     * @param key the key to sign with
     * @return a signature generated from the data and the key
     */
    @JvmStatic
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
    @JvmStatic
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
     * @return a SignedDataContainer
     */
    @JvmStatic
    fun encryptAndSign(
        data: ByteArray,
        encryptionKey: PublicKey,
        signingKey: PrivateKey
    ): SignedDataContainer {
        val enc = encrypt(data, encryptionKey)
        val sig = sign(enc, signingKey)
        return SignedDataContainer(enc, sig)
    }

    /**
     * Encrypts and then signs a piece of data with multiple keys
     *
     * @author Katherine Rose
     * @param data the data to encrypt and sign
     * @param encryptionKeys the keys to use for encryption
     * @param signingKey the key to use for signing
     * @return a SignedDataContainer
     */
    @JvmStatic
    fun encryptAndSign(
        data: ByteArray,
        encryptionKeys: List<PublicKey>,
        signingKey: PrivateKey
    ): SignedDataContainer {
        val enc = encrypt(data, encryptionKeys)
        val sig = sign(enc, signingKey)
        return SignedDataContainer(enc, sig)
    }

    /**
     * Verifies and decrypts data
     *
     * Verifies the data with the signature and verification key, then if the signature is valid, decrypts it with the decryption key
     *
     * This method is different from decryptAndVerify(data, sig, decryptionKey, verification, exceptionOnFailure) because it accepts a SignedDataContainer instead, and you can easily use the output from encryptAndSign(data, encryptionKey, signingKey) directly
     * @author Katherine Rose
     * @param dataAndSig a SignedDataContainer containing the data to decrypt and its signature
     * @param decryptionKey the key to use for decryption
     * @param verificationKey the key to use for verification of the signature
     * @param exceptionOnFailure whether to throw an exception if the signature is invalid or not, if false it will return null instead
     * @return the decrypted data, or null if the signature is invalid and exceptionOnFailure is false
     * @throws SecurityException if the signature is invalid and exceptionOnFailure is true
     */
    @JvmOverloads
    @JvmStatic
    fun decryptAndVerify(
        dataAndSig: SignedDataContainer,
        decryptionKey: PrivateKey,
        verificationKey: PublicKey,
        exceptionOnFailure: Boolean = true
    ): ByteArray? {
        return if (verify(dataAndSig.data, dataAndSig.signature, verificationKey)) decrypt(
            dataAndSig.data,
            decryptionKey
        )
        else if (exceptionOnFailure) throw SecurityException("Signature verification failed.")
        else null
    }

    /**
     * Verifies and decrypts data
     *
     * Same as the other method with the same name, except in this method the data and signature are separated before being passed to the method
     * @author Katherine Rose
     * @param data the data to decrypt
     * @param sig the signature to verify
     * @param decryptionKey the key to use for decryption
     * @param verificationKey the key to use for verification of the signature
     * @param exceptionOnFailure whether to throw an exception if the signature is invalid or not, if false it will return null instead
     * @return the decrypted data, or null if the signature is invalid and exceptionOnFailure is false
     * @throws SecurityException if the signature is invalid and exceptionOnFailure is true
     */
    @JvmOverloads
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