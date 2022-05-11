# Reasonably Easy Cryptography

### *Simple cryptography for everyone.*

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/KiARC/ReasonablyEasyCryptography/CI?style=for-the-badge)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/KiARC/ReasonablyEasyCryptography?style=for-the-badge)
![GitHub Release Date](https://img.shields.io/github/release-date/KiARC/ReasonablyEasyCryptography?style=for-the-badge)

Welcome to **Reasonably Easy Cryptography**, a library designed to do most of the setup for you. Although configuration
is great, sometimes what you need is a library that just works right out of the box. That's why this one exists. The
goal of this project is to create a library that enables anyone to perform encryption and cryptography with minimal work
or understanding of the underlying principals.

## Importing into a project

You can either directly add a release JAR (or one built with `gradle jar`), or you can use `gradle publishToMavenLocal`
to add it to your local Maven repository. If you add it to `mavenLocal` it can be accessed
at `com.katiearose:reasonably-easy-cryptography:[release]`.

## Examples

Numerous examples can be found in [the "examples" directory](examples/) detailing the usage of this library. The files
named "SimplestWay" are meant to illustrate the easiest way to use a subset of the library, such as AES or RSA
encryption.

## Configuration

Although the intent of this project is to minimize configuration, there are optional parameters to most methods to allow
overriding the default settings. They're somewhat self-explanatory so for those who really need them, they're there. If
you don't know what one of them means, you probably don't need to change it.