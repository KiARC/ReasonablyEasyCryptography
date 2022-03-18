package reasonablyEasyCryptography

import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertTrue

class SymmetricEncryptionTest {
    @Test
    fun testEncryptAndDecryptWithKey() {
        val key = SymmetricEncryptionHandler.stringToKey("test")
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
}