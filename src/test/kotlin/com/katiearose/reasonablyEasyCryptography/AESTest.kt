package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertTrue

class AESTest {
    @Test
    fun testEncryptAndDecryptWithKey() {
        val key = AESHandler.generateKey()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AESHandler.encrypt(goal, key)
        val decrypted = AESHandler.decrypt(encrypted, key)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testEncryptAndDecryptWithoutKey() {
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = AESHandler.encrypt(goal, "test")
        val decrypted = AESHandler.decrypt(encrypted, "test")
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testKeyGen() {
        val k1 = AESHandler.generateKey()
        val k2 = AESHandler.generateKey(128)
        val k3 = AESHandler.stringToKey("test")
    }
}