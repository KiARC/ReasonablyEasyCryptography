//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with Foobar. If not, see <https://www.gnu.org/licenses/>.

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