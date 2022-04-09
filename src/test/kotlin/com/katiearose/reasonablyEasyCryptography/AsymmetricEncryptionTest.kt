package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.SignedDataContainer
import org.junit.jupiter.api.Test
import java.util.*
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AsymmetricEncryptionTest {
    @Test
    fun testEncryptAndDecrypt() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encrypt(goal, keys.public)
        val decrypted = RSAEncryptionHandler.decrypt(encrypted, keys.private)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testSignAndVerify() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val signature = RSAEncryptionHandler.sign(goal, keys.private)
        assertTrue(RSAEncryptionHandler.verify(goal, signature, keys.public))
    }

    @Test
    fun testAll() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            RSAEncryptionHandler.decryptAndVerify(encrypted, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testAll2() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            RSAEncryptionHandler.decryptAndVerify(encrypted.data, encrypted.signature, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testAllWithInvalidSig() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val badSig = SignedDataContainer(encrypted.data, fakeSig)
        var failed = false
        try {
            val decrypted = RSAEncryptionHandler.decryptAndVerify(badSig, keys.private, keys.public)
        } catch (e: SecurityException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun testAll2WithInvalidSig() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        var failed = false
        try {
            val decrypted = RSAEncryptionHandler.decryptAndVerify(encrypted.data, fakeSig, keys.private, keys.public)
        } catch (e: SecurityException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun testAllWithInvalidSig2() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val badSig = SignedDataContainer(encrypted.data, fakeSig)
        val decrypted = RSAEncryptionHandler.decryptAndVerify(badSig, keys.private, keys.public, false)
        assertNull(decrypted)
    }

    @Test
    fun testAll2WithInvalidSig2() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted = RSAEncryptionHandler.decryptAndVerify(encrypted.data, fakeSig, keys.private, keys.public, false)
        assertNull(decrypted)
    }

    @Test
    fun testPemGenAndRead() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val pem = PEMHandler.keyPairToPem(keys)
        val keysNew = PEMHandler.pemPairToKeyPair(pem)
        val decrypted = RSAEncryptionHandler.decryptAndVerify(encrypted, keysNew.private, keysNew.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testPemGenAndRead2() {
        val keys = RSAEncryptionHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, keys.public, keys.private)
        val pem = PEMHandler.keyPairToPem(keys)
        val keysNew = PEMHandler.pemPairToKeyPair(pem)
        val decrypted =
            RSAEncryptionHandler.decryptAndVerify(encrypted.data, encrypted.signature, keysNew.private, keysNew.public)
        assertTrue(goal.contentEquals(decrypted))
    }
}