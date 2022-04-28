package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAEncryptionHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.SignedDataContainer
import org.junit.jupiter.api.Test
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
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

    @Test
    fun testPemStream() {
        val num = 10
        val keys = ArrayList<Key>()
        for (ignored in 0 until num) {
            val k = RSAEncryptionHandler.generateKeyPair()
            keys.add(k.private)
            keys.add(k.public)
        }
        var string = ""
        for (i in 0 until num) {
            string += "${PEMHandler.keyToPem(keys[i])}${System.lineSeparator()}"
        }
        val keysUnpemed = ArrayList<Key>()
        PEMHandler.parsePemStream(string.byteInputStream()).forEach {
            keysUnpemed.add(if (it.type == "PRIVATE") PEMHandler.pemToKey(it) as PrivateKey else PEMHandler.pemToKey(it) as PublicKey)
        }
        for (i in 0 until num) {
            assertTrue(keysUnpemed[i].encoded.contentEquals(keys[i].encoded))
        }
    }

    @Test
    fun testEncryptForMultipleRecipients() {
        val recipient1 = RSAEncryptionHandler.generateKeyPair()
        val recipient2 = RSAEncryptionHandler.generateKeyPair()
        val recipientKeys = ArrayList<PublicKey>(2)
        recipientKeys.add(recipient1.public)
        recipientKeys.add(recipient2.public)
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encrypt(goal, recipientKeys)
        val decrypted1 = RSAEncryptionHandler.decrypt(encrypted, recipient1.private)
        val decrypted2 = RSAEncryptionHandler.decrypt(encrypted, recipient2.private)
        assertTrue(decrypted1.contentEquals(goal) && decrypted1.contentEquals(decrypted2))
    }

    @Test
    fun testAllForMultipleRecipients() {
        val sender = RSAEncryptionHandler.generateKeyPair()
        val recipient1 = RSAEncryptionHandler.generateKeyPair()
        val recipient2 = RSAEncryptionHandler.generateKeyPair()
        val recipientKeys = ArrayList<PublicKey>(2)
        recipientKeys.add(recipient1.public)
        recipientKeys.add(recipient2.public)
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAEncryptionHandler.encryptAndSign(goal, recipientKeys, sender.private)
        val decrypted1 =
            RSAEncryptionHandler.decryptAndVerify(encrypted, recipient1.private, sender.public)
        val decrypted2 =
            RSAEncryptionHandler.decryptAndVerify(encrypted, recipient2.private, sender.public)
        assertTrue(decrypted1.contentEquals(goal) && decrypted1.contentEquals(decrypted2))
    }
}