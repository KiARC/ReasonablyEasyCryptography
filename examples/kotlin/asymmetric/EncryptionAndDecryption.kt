//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object EncryptionAndDecryption {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Generate a KeyPair
        val keys = RSAHandler.generateKeyPair()
        //Encrypt data
        val encrypted = RSAHandler.encrypt(plaintext.toByteArray(), keys.public)
        //Decrypt data
        val decrypted = String(RSAHandler.decrypt(encrypted, keys.private))
    }
}
