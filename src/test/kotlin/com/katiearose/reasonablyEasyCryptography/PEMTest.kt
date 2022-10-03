//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

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