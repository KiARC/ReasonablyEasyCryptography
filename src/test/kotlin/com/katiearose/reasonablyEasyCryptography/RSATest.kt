//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

package com.katiearose.reasonablyEasyCryptography

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler
import com.katiearose.reasonablyEasyCryptography.asymmetric.SignedDataContainer
import org.junit.jupiter.api.Test
import java.security.PublicKey
import java.util.*
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RSATest {
    @Test
    fun testEncryptAndDecrypt() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encrypt(goal, keys.public)
        val decrypted = RSAHandler.decrypt(encrypted, keys.private)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testSignAndVerify() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val signature = RSAHandler.sign(goal, keys.private)
        assertTrue(RSAHandler.verify(goal, signature, keys.public))
    }

    @Test
    fun testAll() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            RSAHandler.decryptAndVerify(encrypted, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testAll2() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted =
            RSAHandler.decryptAndVerify(encrypted.data, encrypted.signature, keys.private, keys.public)
        assertTrue(goal.contentEquals(decrypted))
    }

    @Test
    fun testAllWithInvalidSig() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val badSig = SignedDataContainer(encrypted.data, fakeSig)
        var failed = false
        try {
            val decrypted = RSAHandler.decryptAndVerify(badSig, keys.private, keys.public)
        } catch (e: SecurityException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun testAll2WithInvalidSig() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        var failed = false
        try {
            val decrypted = RSAHandler.decryptAndVerify(encrypted.data, fakeSig, keys.private, keys.public)
        } catch (e: SecurityException) {
            failed = true
        }
        assertTrue(failed)
    }

    @Test
    fun testAllWithInvalidSig2() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val badSig = SignedDataContainer(encrypted.data, fakeSig)
        val decrypted = RSAHandler.decryptAndVerify(badSig, keys.private, keys.public, false)
        assertNull(decrypted)
    }

    @Test
    fun testAll2WithInvalidSig2() {
        val keys = RSAHandler.generateKeyPair()
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val fakeSig = ByteArray(256)
        Random().nextBytes(fakeSig)
        val encrypted = RSAHandler.encryptAndSign(goal, keys.public, keys.private)
        val decrypted = RSAHandler.decryptAndVerify(encrypted.data, fakeSig, keys.private, keys.public, false)
        assertNull(decrypted)
    }

    @Test
    fun testEncryptForMultipleRecipients() {
        val recipient1 = RSAHandler.generateKeyPair()
        val recipient2 = RSAHandler.generateKeyPair()
        val recipientKeys = ArrayList<PublicKey>(2)
        recipientKeys.add(recipient1.public)
        recipientKeys.add(recipient2.public)
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encrypt(goal, recipientKeys)
        val decrypted1 = RSAHandler.decrypt(encrypted, recipient1.private)
        val decrypted2 = RSAHandler.decrypt(encrypted, recipient2.private)
        assertTrue(decrypted1.contentEquals(goal) && decrypted1.contentEquals(decrypted2))
    }

    @Test
    fun testAllForMultipleRecipients() {
        val sender = RSAHandler.generateKeyPair()
        val recipient1 = RSAHandler.generateKeyPair()
        val recipient2 = RSAHandler.generateKeyPair()
        val recipientKeys = ArrayList<PublicKey>(2)
        recipientKeys.add(recipient1.public)
        recipientKeys.add(recipient2.public)
        val goal = ByteArray(1024)
        Random().nextBytes(goal)
        val encrypted = RSAHandler.encryptAndSign(goal, recipientKeys, sender.private)
        val decrypted1 =
            RSAHandler.decryptAndVerify(encrypted, recipient1.private, sender.public)
        val decrypted2 =
            RSAHandler.decryptAndVerify(encrypted, recipient2.private, sender.public)
        assertTrue(decrypted1.contentEquals(goal) && decrypted1.contentEquals(decrypted2))
    }

    @Test
    fun testDerivePubFromPriv() {
        val original = RSAHandler.generateKeyPair()
        val derived = RSAHandler.deriveKeyPair(original.private)
        assertTrue { original.public == derived.public && original.private == derived.private }
    }
}