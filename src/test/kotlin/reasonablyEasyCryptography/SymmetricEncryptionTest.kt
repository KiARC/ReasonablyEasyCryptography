package reasonablyEasyCryptography

import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertTrue

class SymmetricEncryptionTest {
    @Test
    fun testEncryptAndDecryptWithKey() {
        val key = SymmetricEncryptionHandler.generateKey()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = SymmetricEncryptionHandler.encrypt(goal, key)
        val decrypted = SymmetricEncryptionHandler.decrypt(encrypted, key)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testEncryptAndDecryptWithoutKey() {
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = SymmetricEncryptionHandler.encrypt(goal, "test")
        val decrypted = SymmetricEncryptionHandler.decrypt(encrypted, "test")
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test fun testKeyGen() {
        val k1 = SymmetricEncryptionHandler.generateKey()
        val k2 = SymmetricEncryptionHandler.generateKey(128)
        val k3 = SymmetricEncryptionHandler.stringToKey("test")
    }
}