package reasonablyEasyCryptography

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


class SymmetricEncryptionHandler {
    companion object {
        private const val algorithm = "AES/GCM/NoPadding"

        /**
         * Generates a new SecretKey with the provided password which can be used for encryption
         *
         * @author Katherine Rose
         * @param password the desired password
         * @return a new SecretKey instance
         */
        fun stringToKey(password: String): SecretKey {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
        }

        /**
         * Generates a new SecretKey with the provided password which can be used for encryption
         *
         * This method also returns the salt. You probably don't need it, but it is used for the methods that encrypt data using "only" a password since they store the salt with the ciphertext
         * @author Katherine Rose
         * @param password the desired password
         * @return a new Pair containing a SecretKey instance and its salt
         */
        fun stringToKeyAndSalt(password: String): Pair<SecretKey, ByteArray> {
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)
            val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
            return Pair(SecretKeySpec(factory.generateSecret(spec).encoded, "AES"), salt)
        }

        /**
         * Generates a new SecretKey with the provided password and salt which can be used for encryption
         *
         * This method is best used in tandem with stringToKeyAndSalt(String) to generate and save keys
         * @author Katherine Rose
         * @param password the desired password
         * @param salt the desired salt
         * @return a new SecretKey instance
         */
        fun stringAndSaltToKey(password: String, salt: ByteArray): SecretKey {
            val spec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
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
         * @return unencrypted data encrypted with password
         */
        fun encrypt(plain: ByteArray, key: SecretKey): ByteArray {
            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)
            val cipher = Cipher.getInstance(algorithm)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.encoded, "AES"), GCMParameterSpec(128, nonce))
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
         * @return unencrypted data encrypted with password
         */
        fun encrypt(plain: ByteArray, key: String): ByteArray {
            val nonce = ByteArray(12)
            SecureRandom().nextBytes(nonce)
            val cipher = Cipher.getInstance(algorithm)
            val keyAndSalt = stringToKeyAndSalt(key)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keyAndSalt.first.encoded, "AES"),
                GCMParameterSpec(128, nonce)
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
         * @param encrypted the encrypted ByteArray to decrypt
         * @param key the key to use to decrypt plain
         * @return encrypted data decrypted with key
         */
        fun decrypt(encrypted: ByteArray, key: SecretKey): ByteArray {
            val buffer = ByteBuffer.wrap(encrypted)
            val nonce = ByteArray(12)
            buffer.get(nonce)
            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)
            val cipher: Cipher = Cipher.getInstance(algorithm)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.encoded, "AES"), GCMParameterSpec(128, nonce))
            return cipher.doFinal(ciphertext)
        }

        /**
         * Decrypts a provided ByteArray using a provided password
         *
         * Underlying algorithm is AES-GCM
         *
         * @author Katherine Rose
         * @param encrypted the encrypted ByteArray to decrypt
         * @param key the password to use to decrypt plain
         * @return encrypted data decrypted with password
         */
        fun decrypt(encrypted: ByteArray, key: String): ByteArray {
            val buffer = ByteBuffer.wrap(encrypted)
            val salt = ByteArray(16)
            buffer.get(salt)
            val nonce = ByteArray(12)
            buffer.get(nonce)
            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)
            val cipher: Cipher = Cipher.getInstance(algorithm)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(stringAndSaltToKey(key, salt).encoded, "AES"),
                GCMParameterSpec(128, nonce)
            )
            return cipher.doFinal(ciphertext)
        }
    }
}