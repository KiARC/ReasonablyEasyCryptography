//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

package com.katiearose.reasonablyEasyCryptography.asymmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler
import java.nio.ByteBuffer
import java.security.*
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.RSAPublicKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.SecretKey


/**
 * Static methods to handle RSA cryptography (keygen, sign/verify and encrypt/decrypt)
 *
 * @author Katherine Rose
 */
object RSAHandler {
    //Sane Defaults
    const val DEFAULT_ENC_ALGO = "RSA/ECB/OAEPwithSHA-256andMGF1Padding"
    const val DEFAULT_SIG_ALGO = "SHA256withRSA"
    const val DEFAULT_KEY_SIZE = 2048
    const val DEFAULT_SECRET_SIZE = 256

    /**
     * Generates an RSA KeyPair of a given keysize to be used for encryption
     *
     * @author Katherine Rose
     * @param keySize the size in bits of the key to generate (optional)
     * @return a new KeyPair
     */
    @JvmOverloads
    @JvmStatic
    fun generateKeyPair(keySize: Int = DEFAULT_KEY_SIZE): KeyPair {
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
     * @param algorithm the algorithm to use for encryption (optional)
     * @param secretKeySize the size of the AES secret key to use for encryption (optional)
     * @return the encrypted data and its encrypted symmetric key
     */
    @JvmOverloads
    @JvmStatic
    fun encrypt(
        data: ByteArray,
        key: PublicKey,
        algorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE
    ): ByteArray {
        val k = AESHandler.generateKey(secretKeySize)
        val encryptedData = AESHandler.encrypt(data, k)
        val c = Cipher.getInstance(algorithm)
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
     * @param algorithm the algorithm to use for encryption (optional)
     * @param secretKeySize the size of the AES secret key to use for encryption (optional)
     * @return the encrypted data and its encrypted symmetric keys
     */
    @JvmOverloads
    @JvmStatic
    fun encrypt(
        data: ByteArray,
        keys: List<PublicKey>,
        algorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE
    ): ByteArray {
        if (keys.size > 256) {
            throw RuntimeException("More than 256 recipients specified at once")
        }
        val encryptedSecrets = ArrayList<ByteArray>(keys.size)
        val k = AESHandler.generateKey(secretKeySize)
        val encryptedData = AESHandler.encrypt(data, k)
        for (key in keys) {
            val c = Cipher.getInstance(algorithm)
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
     * @param algorithm the algorithm to use for decryption (optional, must be the same as the value used for encryption)
     * @param secretKeySize the size of the AES secret key to use for decryption (optional, must be the same as the value used for encryption)
     * @return the decrypted data
     */
    @JvmOverloads
    @JvmStatic
    fun decrypt(
        data: ByteArray,
        key: PrivateKey,
        algorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE
    ): ByteArray {
        val c = Cipher.getInstance(algorithm)
        c.init(Cipher.DECRYPT_MODE, key)
        val buffer = ByteBuffer.wrap(data)
        val rbyte = ByteArray(1)
        buffer.get(rbyte)
        val recipientCount = rbyte[0].toUByte()
        val kbs = ArrayDeque<ByteArray>()
        for (i in 0 until recipientCount.toInt() + 1) {
            val kB = ByteArray(secretKeySize)
            buffer.get(kB)
            kbs.addFirst(kB)
        }
        var foundKey = false
        var k: SecretKey? = null
        while (!foundKey) {
            try {
                k = AESHandler.assembleKey(c.doFinal(kbs.removeFirst()))
                foundKey = true
            } catch (_: BadPaddingException) { /*Ignore that, it just means that wasn't the right one*/
            }
        }
        if (k == null) {
            throw SecurityException("Could not successfully decrypt a key, was this message encrypted for this keypair?")
        }
        val enc = ByteArray(buffer.remaining())
        buffer.get(enc)
        return AESHandler.decrypt(enc, k)
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
        val k = AESHandler.assembleKey(c.doFinal(kB))
        return AESHandler.decrypt(enc, k)
    }

    /**
     * Signs data with a given private key
     *
     * @author Katherine Rose
     * @param data the data to sign
     * @param key the key to sign with
     * @param algorithm the algorithm to use for signing (optional)
     * @return a signature generated from the data and the key
     */
    @JvmOverloads
    @JvmStatic
    fun sign(data: ByteArray, key: PrivateKey, algorithm: String = DEFAULT_SIG_ALGO): ByteArray {
        val s = Signature.getInstance(algorithm)
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
     * @param algorithm the algorithm to use for verification (optional, must be the same as the value used for signing)
     * @return true if the signature is valid, false if not
     */
    @JvmOverloads
    @JvmStatic
    fun verify(data: ByteArray, sig: ByteArray, key: PublicKey, algorithm: String = DEFAULT_SIG_ALGO): Boolean {
        val s = Signature.getInstance(algorithm)
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
     * @param encryptionAlgorithm the algorithm to use for encryption (optional)
     * @param secretKeySize the size of the AES secret key to use for encryption (optional)
     * @param signatureAlgorithm the algorithm to use for signing (optional)
     * @return a SignedDataContainer
     */
    @JvmOverloads
    @JvmStatic
    fun encryptAndSign(
        data: ByteArray,
        encryptionKey: PublicKey,
        signingKey: PrivateKey,
        encryptionAlgorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE,
        signatureAlgorithm: String = DEFAULT_SIG_ALGO
    ): SignedDataContainer {
        val enc = encrypt(data, encryptionKey, encryptionAlgorithm, secretKeySize)
        val sig = sign(enc, signingKey, signatureAlgorithm)
        return SignedDataContainer(enc, sig)
    }

    /**
     * Encrypts and then signs a piece of data with multiple keys
     *
     * @author Katherine Rose
     * @param data the data to encrypt and sign
     * @param encryptionKeys the keys to use for encryption
     * @param signingKey the key to use for signing
     * @param encryptionAlgorithm the algorithm to use for encryption (optional)
     * @param secretKeySize the size of the AES secret key to use for encryption (optional)
     * @param signatureAlgorithm the algorithm to use for signing (optional)
     * @return a SignedDataContainer
     */
    @JvmOverloads
    @JvmStatic
    fun encryptAndSign(
        data: ByteArray,
        encryptionKeys: List<PublicKey>,
        signingKey: PrivateKey,
        encryptionAlgorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE,
        signatureAlgorithm: String = DEFAULT_SIG_ALGO
    ): SignedDataContainer {
        val enc = encrypt(data, encryptionKeys, encryptionAlgorithm, secretKeySize)
        val sig = sign(enc, signingKey, signatureAlgorithm)
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
     * @param decryptionAlgorithm the algorithm to use for decryption (optional, must be the same as the value used for encryption)
     * @param secretKeySize the size of the AES secret key to use for decryption (optional, must be the same as the value used for encryption)
     * @param verificationAlgorithm the algorithm to use for verification (optional, must be the same as the value used for signing)
     * @return the decrypted data, or null if the signature is invalid and exceptionOnFailure is false
     * @throws SecurityException if the signature is invalid and exceptionOnFailure is true
     */
    @JvmOverloads
    @JvmStatic
    fun decryptAndVerify(
        dataAndSig: SignedDataContainer,
        decryptionKey: PrivateKey,
        verificationKey: PublicKey,
        exceptionOnFailure: Boolean = true,
        decryptionAlgorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE,
        verificationAlgorithm: String = DEFAULT_SIG_ALGO
    ): ByteArray? {
        return if (verify(dataAndSig.data, dataAndSig.signature, verificationKey, verificationAlgorithm)) decrypt(
            dataAndSig.data,
            decryptionKey,
            decryptionAlgorithm,
            secretKeySize
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
     * @param decryptionAlgorithm the algorithm to use for decryption (optional, must be the same as the value used for encryption)
     * @param secretKeySize the size of the AES secret key to use for decryption (optional, must be the same as the value used for encryption)
     * @param verificationAlgorithm the algorithm to use for verification (optional, must be the same as the value used for signing
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
        exceptionOnFailure: Boolean = true,
        decryptionAlgorithm: String = DEFAULT_ENC_ALGO,
        secretKeySize: Int = DEFAULT_SECRET_SIZE,
        verificationAlgorithm: String = DEFAULT_SIG_ALGO
    ): ByteArray? {
        return if (verify(data, sig, verificationKey, verificationAlgorithm)) decrypt(
            data,
            decryptionKey,
            decryptionAlgorithm,
            secretKeySize
        )
        else if (exceptionOnFailure) throw SecurityException("Signature verification failed.")
        else null
    }

    fun deriveKeyPair(privateKey: PrivateKey): KeyPair {
        val privateKeyCert = privateKey as RSAPrivateCrtKey
        val publicKeySpec = RSAPublicKeySpec(privateKeyCert.modulus, privateKeyCert.publicExponent)
        val keyFactory = KeyFactory.getInstance("RSA")
        return KeyPair(keyFactory.generatePublic(publicKeySpec), privateKey)
    }
}
