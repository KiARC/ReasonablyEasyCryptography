package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.symmetric.AESEncryptionHandler
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertTrue

class SymmetricEncryptionTest {
    @Test
    fun testEncryptAndDecryptWithKey() {
        val key = AESEncryptionHandler.generateKey()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AESEncryptionHandler.encrypt(goal, key)
        val decrypted = AESEncryptionHandler.decrypt(encrypted, key)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testEncryptAndDecryptWithoutKey() {
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AESEncryptionHandler.encrypt(goal, "test")
        val decrypted = AESEncryptionHandler.decrypt(encrypted, "test")
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testKeyGen() {
        val k1 = AESEncryptionHandler.generateKey()
        val k2 = AESEncryptionHandler.generateKey(128)
        val k3 = AESEncryptionHandler.stringToKey("test")
    }
}