//Copyright 2022 Katherine Rose
//This file is part of ReasonablyEasyCryptography.
//ReasonablyEasyCryptography is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//ReasonablyEasyCryptography is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//You should have received a copy of the GNU Lesser General Public License along with ReasonablyEasyCryptography. If not, see <https://www.gnu.org/licenses/

>. package java.symmetric;

import com.katiearose.reasonablyEasyCryptography.symmetric.AESHandler;

import javax.crypto.SecretKey;

public class SerializingAndDeserializingAKey {
    public static void main(String[] args) {
        //Create your key however you want, I'll use REC but this works with any javax.crypto.SecretKey
        SecretKey key1 = AESHandler.generateKey();
        //Get the encoded form of the key
        byte[] encoded = key1.getEncoded();
        //The key is now serialized, and REC makes it easy to deserialize it
        SecretKey key2 = AESHandler.assembleKey(encoded);
        //key2 is able to decrypt things encrypted with key1 and vice versa, because they're the same key.
    }
}
