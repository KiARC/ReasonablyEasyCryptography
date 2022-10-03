//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package kotlin.asymmetric

import com.katiearose.reasonablyEasyCryptography.asymmetric.RSAHandler

object SigningAndVerifying {
    @JvmStatic
    fun main(args: Array<String>) {
        //Define message
        val message = "Hello World!"
        //Generate a KeyPair
        val keys = RSAHandler.generateKeyPair()
        //Generate signature
        val signature = RSAHandler.sign(message.toByteArray(), keys.private)
        //Verify signature, value will be true if the signature is good and false if it's bad
        val isValid = RSAHandler.verify(message.toByteArray(), signature, keys.public)
    }
}
