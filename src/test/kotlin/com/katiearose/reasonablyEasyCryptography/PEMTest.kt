package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.asymmetric.PEMHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler
import org.junit.jupiter.api.Test
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import kotlin.test.assertTrue

class PEMTest {
    @Test
    fun testPemGenAndRead() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val pem = PEMHandler.keyPairToPem(keys)
        val keysNew = PEMHandler.pemPairToKeyPair(pem)
        val decrypted = RSAHandler.decryptAndVerify(encrypted, keysNew.private, keysNew.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testPemGenAndRead2() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val pem = PEMHandler.keyPairToPem(keys)
        val keysNew = PEMHandler.pemPairToKeyPair(pem)
        val decrypted =
            RSAHandler.decryptAndVerify(encrypted.data, encrypted.signature, keysNew.private, keysNew.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testPemStream() {
        val num = 10
        val keys = ArrayList<Key>()
        for (ignored in 0 until num) {
            val k = RSAHandler.generateKeyPair()
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
}