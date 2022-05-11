# Reasonably Easy Cryptography

### *Simple cryptography for everyone.*

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/KiARC/ReasonablyEasyCryptography/CI?style=for-the-badge)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/KiARC/ReasonablyEasyCryptography?style=for-the-badge)
![GitHub Release Date](https://img.shields.io/github/release-date/KiARC/ReasonablyEasyCryptography?style=for-the-badge)

Welcome to **Reasonably Easy Cryptography**, a library designed to from the ground up to provide sane defaults and to
minimize the amount of code you need to write to do cryptography in your own projects. REC's goal is to have a default
value for every feasible parameter so that you can spend less time configuring and more time working on other things.
REC is not inflexible, however, as nearly all of these defaults can be easily overridden with simple parameters. Whether
you're just looking to get encryption over with, or a total cryptography nerd wanting to play with different
configurations, REC is the tool for you.

## Importing into a project

Download the latest release from the releases page and add it to your dependencies in your IDE.

## Examples

Numerous examples can be found in [the "examples" directory](examples/) detailing the usage of this library. The files
named "SimplestWay" are meant to illustrate the easiest way to use a subset of the library, such as AES or RSA
encryption.

## Configuration

Although the intent of this project is to minimize configuration, there are optional parameters to most methods to allow
overriding the default settings. They're somewhat self-explanatory so for those who really need them, they're there. If
you don't know what one of them means, you probably don't need to change it.