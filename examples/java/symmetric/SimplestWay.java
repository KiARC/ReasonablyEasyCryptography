//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler;

public class SimplestWay {
    public static void main(String[] args) {
        //Define plaintext
        String plaintext = "Hello World!";
        //Encrypt it with a password
        byte[] ciphertext = AESHandler.encrypt(plaintext.getBytes(), "password");
        //Decrypt it with the same password
        String decrypted = new String(AESHandler.decrypt(ciphertext, "password"));
    }
}
