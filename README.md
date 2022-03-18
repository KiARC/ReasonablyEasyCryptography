# Reasonably Easy Cryptography

### *Tired of libraries with great features but a huge amount of setup? This is the repo for you.*

Welcome to **Reasonably Easy Cryptography**, a library designed to do most of the setup for you. Although configuration
is great, sometimes what you need is a library that just works. That's why this one exists. The goal of this project is
to create a library that enables anyone to perform encryption and cryptography with minimal work or understanding of the
underlying principals.

## Usage
### Symmetric Encryption via AES-GCM
#### Encrypt data with a key object
```kotlin
val key = SymmetricEncryptionHandler.stringToKey(password)      //Where password is the desired password for the key
val encrypted = SymmetricEncryptionHandler.encrypt(data, key)   //Where data is a ByteArray to be encrypted
```
#### Decrypt data with a key object
```kotlin
val key = SymmetricEncryptionHandler.stringToKey(password)      //Where password is the desired password for the key
val decrypted = SymmetricEncryptionHandler.decrypt(data, key)   //Where data is a ByteArray to be decrypted
```
#### Encrypt data without a key object
```kotlin
val encrypted = SymmetricEncryptionHandler.encrypt(data, password)  //Where data is a ByteArray to be encrypted and
                                                                    //password is a String to use as a password
```
Note: The return value of this will be sixteen bytes larger than if a key object is used. This is due to the method storing the password salt in the output.
#### Decrypt data without a key object
```kotlin
val decrypted = SymmetricEncryptionHandler.decrypt(data, password)  //Where data is a ByteArray to be decrypted and
                                                                    //password is a String to use as a password
```
### Asymmetric Encryption/Signing via RSA
#### Generate a Key Pair
```kotlin
val keys = AsymmetricEncryptionHandler.generateKeyPair()
```
#### Encrypt Data
```kotlin
val encrypted = AsymmetricEncryptionHandler.encrypt(data, key)  //Where data is a ByteArray to be encrypted and
                                                                //key is a public key to use for encryption
```
#### Decrypt Data
```kotlin
val decrypted = AsymmetricEncryptionHandler.decrypt(data, key)  //Where data is a ByteArray to be decrypted and
                                                                //key is a private key to use for decryption 
```
#### Sign Data
```kotlin
val signature = AsymmetricEncryptionHandler.decrypt(data, key)  //Where data is a ByteArray to be signed and 
                                                                //key is a private key to use for signing
```
#### Verify a Signature
```kotlin
val isValid = AsymmetricEncryptionHandler.verify(data, signature, key)  //Where data is the ByteArray that the signature belongs to,
                                                                        //signature is the signature for that data and key
                                                                        //is the public counterpart to the key that generated the
                                                                        //signature
```
### Sign and Encrypt Data in One Call
```kotlin
val output = AsymmetricEncryptionHandler.encryptAndSign(data, publicKey, privateKey)    //Where data is a ByteArray to be signed and encrypted, 
                                                                                        //publicKey is the key to encrypt the data with and
                                                                                        //privateKey is the key to sign the data with. The result
                                                                                        //is a SignedDataContainer containing the data and its signature
```
### Decrypt and Verify Data in One Call
```kotlin
val decrypted = AsymmetricEncryptionHandler.decryptAndVerify(data, privateKey, publicKey, exceptionOnFailure)
//Where data is a SignedDataContainer, privateKey is the key to decrypt the data with, publicKey is the key to verify the
//signature with, and exceptionOnFailure is a boolean representing whether the method should throw an exception if verification
//fails or not. The result is the decrypted data if the signature is valid, or null if it is invalid and exceptionOnFailure is
//false. exceptionOnFailure can be omitted, and the default value is true.
```
### Alternative Method to Decrypt and Verify Data in One Call
```kotlin
val decrypted = AsymmetricEncryptionHandler.decryptAndVerify(data, signature, privateKey, publicKey, exceptionOnFailure)
//Same as above, except that instead of a single SignedDataContainer this method takes the two ByteArrays separately.
```