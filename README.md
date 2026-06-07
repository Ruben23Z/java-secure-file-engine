# Applied Cryptography in Java — Symmetric Cipher & Digital Signature

A Java security system implementing **authenticated encryption with AES-CBC + HMAC-SHA256** and **RSA digital signing/verification**, developed for the **Computer Security** course in the Computer Engineering and Multimedia degree at ISEL.

---

## Context

Built as a practical assignment for the **Computer Security** curricular unit, with the goal of implementing two fundamental cryptographic security mechanisms from scratch in Java:

- **Confidentiality and integrity** of files via authenticated symmetric encryption
- **Authenticity and non-repudiation** via digital signatures with a PKI certificate chain

All cryptographic operations were implemented directly against the **JCA/JCE** (*Java Cryptography Architecture/Extension*) APIs, without high-level libraries, providing a low-level understanding of the underlying mechanisms.

---

## Features

- **File encryption** with AES-CBC (128-bit) and PKCS5 padding, with automatic random IV generation per operation
- **Cipher authentication** via HMAC-SHA256 using the *Encrypt-then-MAC* scheme — integrity is verified before any decryption
- **RSA digital signing** of arbitrary files (SHA-1 and SHA-256 supported), reading the private key from a PKCS12 KeyStore
- **Signature verification** with full X.509 certificate chain validation (leaf → intermediate → trust anchor)
- **Automatic key management** — generation and persistence to a binary file when no key exists yet
- **Large file support** via incremental 8KB block reads

---

## Technologies

- **Java 25**
- **JCA/JCE** — Java Cryptography Architecture/Extension
- **AES-CBC** with PKCS5Padding
- **HMAC-SHA256**
- **RSA** — SHA1withRSA / SHA256withRSA
- **X.509 / PKIX** — certificate chain validation
- **PKCS12** — KeyStore format for private key + certificate

---

## Architecture

| Class | Responsibility |
|---|---|
| `seginf.CriptoUtil` | Key/IV generation, HMAC computation, Base64 encoding |
| `seginf.AEEengine` | Authenticated encrypt/decrypt engine (Encrypt-then-MAC) |
| `seginf.AEapp` | CLI application for file encryption/decryption |
| `AssinaturaDigital.RSASignVerify` | RSA signing and verification with PKIX chain validation |

---

## What I Learned

- **Encrypt-then-MAC** — correct operation ordering in authenticated encryption and the consequences of reversing it
- **IV management** — importance of randomness and uniqueness of the initialisation vector per cipher operation
- **PKI and trust chains** — PKIX validation with configurable trust anchors, distinguishing valid certificates across different CA hierarchies
- **Incremental reads** — secure processing of large files without loading content fully into memory
- **Key separation** — using distinct keys for AES and HMAC to avoid cryptographic material reuse
