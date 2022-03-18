package reasonablyEasyCryptography

import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertTrue

class AsymmetricEncryptionTest {
    @Test
    fun testEncryptAndDecrypt() {
        val keys = AsymmetricEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AsymmetricEncryptionHandler.encrypt(goal, keys.public)
        val decrypted = AsymmetricEncryptionHandler.decrypt(encrypted, keys.private)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testSignAndVerify() {
        val keys = AsymmetricEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val signature = AsymmetricEncryptionHandler.sign(goal, keys.private)
        assertTrue(AsymmetricEncryptionHandler.verify(goal, signature, keys.public))
    }

    @Test
    fun testAll() {
        val keys = AsymmetricEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AsymmetricEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            AsymmetricEncryptionHandler.decryptAndVerify(encrypted.first, encrypted.second, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testAll2() {
        val keys = AsymmetricEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AsymmetricEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            AsymmetricEncryptionHandler.decryptAndVerify(encrypted, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }
}