//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.symmetric

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler

object KeyObjectWithPassword {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define plaintext
        val plaintext = "Hello World!"
        //Create a SecretKey using a password
        val key = AESHandler.stringToKey("password")
        //Encrypt the plaintext with it
        val ciphertext = AESHandler.encrypt(plaintext.toByteArray(), key)
        //Decrypt it with the same key
        val decrypted = String(AESHandler.decrypt(ciphertext, key))
    }
}
