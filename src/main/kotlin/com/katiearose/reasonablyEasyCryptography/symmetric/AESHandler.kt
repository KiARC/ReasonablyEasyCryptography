package com.katiearose.reasonablyEasyCryptography.symmetric

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Static methods to handle AES cryptography (keygen and encrypt/decrypt)
 *
 * @author Katherine Rose
 */
object AESHandler {
    //Sane Defaults
    //Padding doesn't do anything when using GCM but hey why not, it won't break anything
    const val DEFAULT_ENC_PADDING = "NoPadding"
    const val DEFAULT_KD_ALGO = "PBKDF2WithHmacSHA1"
    const val DEFAULT_SALT_SIZE = 16
    const val DEFAULT_NONCE_SIZE = 12
    const val DEFAULT_TAG_LENGTH = 128
    const val DEFAULT_KEY_LENGTH = 256
    const val DEFAULT_ITERATION_COUNT = 65536


    /**
     * Generates a new SecretKey with the provided password which can be used for encryption
     *
     * @author Katherine Rose
     * @param password the desired password
     * @param algorithm the algorithm to use for key derivation (optional)
     * @param saltSize the size of the salt to use for key derivation (optional)
     * @param keyLength the desired length of the returned key (optional)
     * @param iterationCount the number of iterations to use when deriving the key (optional)
     * @return a new SecretKey instance
     */
    @JvmOverloads
    @JvmStatic
    fun stringToKey(
        password: String,
        algorithm: String = DEFAULT_KD_ALGO,
        saltSize: Int = DEFAULT_SALT_SIZE,
        keyLength: Int = DEFAULT_KEY_LENGTH,
        iterationCount: Int = DEFAULT_ITERATION_COUNT
    ): SecretKey {
        val salt = ByteArray(saltSize)
        SecureRandom().nextBytes(salt)
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val factory = SecretKeyFactory.getInstance(algorithm)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    /**
     * Generates a new SecretKey from random bytes which can be used for encryption
     *
     * @author Katherine Rose
     * @param keySize the keySize to use for key generation (optional)
     * @return a new SecretKey instance
     */
    @JvmOverloads
    @JvmStatic
    fun generateKey(keySize: Int = DEFAULT_KEY_LENGTH): SecretKey {
        val kg = KeyGenerator.getInstance("AES")
        kg.init(keySize)
        return kg.generateKey()
    }

    /**
     * Assembles a new SecretKey from bytes which can be used for encryption
     *
     * @author Katherine Rose
     * @param data the bytes to reconstruct, for example from SecretKey.encoded
     * @return a new SecretKey instance
     */
    @JvmStatic
    fun assembleKey(data: ByteArray): SecretKey {
        return SecretKeySpec(data, 0, data.size, "AES")
    }

    /**
     * Generates a new SecretKey with the provided password which can be used for encryption
     *
     * This method also returns the salt. You probably don't need it, but it is used for the methods that encrypt data using "only" a password since they store the salt with the ciphertext
     *
     * Warning: Incompatible with Java, due to the return type being a Pair. This may be changed later.
     *
     * @author Katherine Rose
     * @param password the desired password
     * @param algorithm the algorithm to use for key derivation (optional)
     * @param saltSize the size of the salt to use for key derivation (optional)
     * @param keyLength the desired length of the returned key (optional)
     * @param iterationCount the number of iterations to use when deriving the key (optional)
     * @return a new Pair containing a SecretKey instance and its salt
     */
    @JvmOverloads
    @JvmStatic
    fun stringToKeyAndSalt(
        password: String,
        algorithm: String = DEFAULT_KD_ALGO,
        saltSize: Int = DEFAULT_SALT_SIZE,
        keyLength: Int = DEFAULT_KEY_LENGTH,
        iterationCount: Int = DEFAULT_ITERATION_COUNT
    ): Pair<SecretKey, ByteArray> { //TODO Change return type to be Java compatible
        val salt = ByteArray(saltSize)
        SecureRandom().nextBytes(salt)
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val factory = SecretKeyFactory.getInstance(algorithm)
        return Pair(SecretKeySpec(factory.generateSecret(spec).encoded, "AES"), salt)
    }

    /**
     * Generates a new SecretKey with the provided password and salt which can be used for encryption
     *
     * This method is best used in tandem with stringToKeyAndSalt(String) to generate and save keys
     * @author Katherine Rose
     * @param password the desired password
     * @param salt the desired salt
     * @param algorithm the algorithm to use for key derivation (optional)
     * @param saltSize the size of the salt to use for key derivation (optional)
     * @param keyLength the desired length of the returned key (optional)
     * @param iterationCount the number of iterations to use when deriving the key (optional)
     * @return a new SecretKey instance
     */
    @JvmOverloads
    @JvmStatic
    fun stringAndSaltToKey(
        password: String,
        salt: ByteArray,
        algorithm: String = DEFAULT_KD_ALGO,
        keyLength: Int = DEFAULT_KEY_LENGTH,
        iterationCount: Int = DEFAULT_ITERATION_COUNT
    ): SecretKey {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val factory = SecretKeyFactory.getInstance(algorithm)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    /**
     * Encrypts a provided ByteArray using a provided SecretKey
     *
     * Underlying algorithm is AES-GCM
     *
     * @author Katherine Rose
     * @param plain the unencrypted ByteArray to encrypt
     * @param key the key to use to encrypt plain
     * @param padding the padding to use for encryption (optional)
     * @param nonceSize the size of the nonce to use for encryption (optional)
     * @param tagLength the length of the tag to use for encryption (optional)
     * @return plain encrypted with key
     */
    @JvmOverloads
    @JvmStatic
    fun encrypt(
        plain: ByteArray,
        key: SecretKey,
        padding: String = DEFAULT_ENC_PADDING,
        nonceSize: Int = DEFAULT_NONCE_SIZE,
        tagLength: Int = DEFAULT_TAG_LENGTH
    ): ByteArray {
        val nonce = ByteArray(nonceSize)
        SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/$padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encoded, "AES"), GCMParameterSpec(tagLength, nonce))
        val ciphertext = cipher.doFinal(plain)
        val output = ByteBuffer.allocate(nonce.size + ciphertext.size)
        output.put(nonce)
        output.put(ciphertext)
        return output.array()
    }

    /**
     * Encrypts a provided ByteArray using a provided password
     *
     * Underlying algorithm is AES-GCM. Output is slightly larger than the other encryption method in this class because the 16 byte salt must be stored with the ciphertext.
     *
     * @author Katherine Rose
     * @param plain the unencrypted ByteArray to encrypt
     * @param key the password to use to encrypt plain
     * @param padding the padding to use for encryption (optional)
     * @param nonceSize the size of the nonce to use for encryption (optional)
     * @param tagLength the length of the tag to use for encryption (optional)
     * @return plain encrypted with SecretKey derived from key, as well as the salt used for derivation
     */
    @JvmOverloads
    @JvmStatic
    fun encrypt(
        plain: ByteArray,
        key: String,
        padding: String = DEFAULT_ENC_PADDING,
        nonceSize: Int = DEFAULT_NONCE_SIZE,
        tagLength: Int = DEFAULT_TAG_LENGTH
    ): ByteArray {
        val nonce = ByteArray(nonceSize)
        SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/$padding")
        val keyAndSalt = stringToKeyAndSalt(key)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(keyAndSalt.first.encoded, "AES"),
            GCMParameterSpec(tagLength, nonce)
        )
        val ciphertext = cipher.doFinal(plain)
        val output = ByteBuffer.allocate(keyAndSalt.second.size + nonce.size + ciphertext.size)
        output.put(keyAndSalt.second)
        output.put(nonce)
        output.put(ciphertext)
        return output.array()
    }

    /**
     * Decrypts a provided ByteArray using a provided SecretKey
     *
     * Underlying algorithm is AES-GCM
     *
     * @author Katherine Rose
     * @param ciphertext the encrypted ByteArray to decrypt
     * @param key the key to use to decrypt plain
     * @param padding the padding to use for decryption (optional, must be the same as the value used for encryption)
     * @param nonceSize the size of the nonce to use for encryption (optional)
     * @param tagLength the length of the tag to use for encryption (optional)
     * @return ciphertext decrypted using key
     */
    @JvmOverloads
    @JvmStatic
    fun decrypt(
        ciphertext: ByteArray,
        key: SecretKey,
        padding: String = DEFAULT_ENC_PADDING,
        nonceSize: Int = DEFAULT_NONCE_SIZE,
        tagLength: Int = DEFAULT_TAG_LENGTH
    ): ByteArray {
        val buffer = ByteBuffer.wrap(ciphertext)
        val nonce = ByteArray(nonceSize)
        buffer.get(nonce)
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        val cipher: Cipher = Cipher.getInstance("AES/GCM/$padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.encoded, "AES"), GCMParameterSpec(tagLength, nonce))
        return cipher.doFinal(data)
    }

    /**
     * Decrypts a provided ByteArray using a provided password
     *
     * Underlying algorithm is AES-GCM
     *
     * @author Katherine Rose
     * @param ciphertext the encrypted ByteArray to decrypt
     * @param key the password to use to decrypt plain
     * @param padding the padding to use for decryption (optional, must be the same as the value used for encryption)
     * @param nonceSize the size of the nonce to use for encryption (optional)
     * @param tagLength the length of the tag to use for encryption (optional)
     * @return ciphertext decrypted with a SecretKey derived using the contained salt and key
     */
    @JvmOverloads
    @JvmStatic
    fun decrypt(
        ciphertext: ByteArray,
        key: String,
        padding: String = DEFAULT_ENC_PADDING,
        saltSize: Int = DEFAULT_SALT_SIZE,
        nonceSize: Int = DEFAULT_NONCE_SIZE,
        tagLength: Int = DEFAULT_TAG_LENGTH
    ): ByteArray {
        val buffer = ByteBuffer.wrap(ciphertext)
        val salt = ByteArray(saltSize)
        buffer.get(salt)
        val nonce = ByteArray(nonceSize)
        buffer.get(nonce)
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        val cipher: Cipher = Cipher.getInstance("AES/GCM/$padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(stringAndSaltToKey(key, salt).encoded, "AES"),
            GCMParameterSpec(tagLength, nonce)
        )
        return cipher.doFinal(data)
    }
}