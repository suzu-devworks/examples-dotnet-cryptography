# AES (Advanced Encryption Standard)

## Table of Contents <!-- omit in toc -->

- [Overview](#overview)
- [Block cipher mode of operation](#block-cipher-mode-of-operation)
  - [Authenticated encryption with additional data (AEAD) modes](#authenticated-encryption-with-additional-data-aead-modes)
  - [Confidentiality only modes](#confidentiality-only-modes)
- [References](#references)

## Overview

AES is a symmetric-key block cipher algorithm that was standardized by the United States in 2001. The U.S. National Institute of Standards and Technology (NIST) ran an open competition, and the Rijndael cipher was selected and standardized as AES.

<!-- spell-checker:words Rijndael -->

## Block cipher mode of operation

A mechanism for encrypting messages longer than the block size by using a block cipher.

### Authenticated encryption with additional data (AEAD) modes

Authenticated encryption modes.

They produce ciphertext while simultaneously generating authentication information (an authentication tag).

- GCM (Galois/Counter Mode)
    > A mode that combines counter-mode encryption with a new Galois-field-based authentication mode.  
    > Because the Galois field multiplications used for authentication can be easily computed in parallel, GCM can achieve higher throughput than the underlying block cipher.
- CCM (Counter with CBC-MAC)  
    > An AES-based mode that combines counter-mode encryption with CBC-MAC authentication.  
CCM is essentially the same as CCMP, which is used in WPA2.
- [RFC 5084 ...](https://datatracker.ietf.org/doc/html/rfc5084)

### Confidentiality only modes

Modes that provide confidentiality only (no built-in integrity or authenticity).

- ECB (Electronic Codebook mode)
    > The simplest block cipher mode. The message is divided into blocks, and each block is encrypted independently.
- CBC (Cipher Block Chaining mode)
    > Each plaintext block is XORed with the previous ciphertext block before being encrypted. As a result, each ciphertext block depends on all preceding plaintext blocks. An initialization vector (IV) is used when encrypting the first block.
- CFB (Cipher Feedback mode)
    > Feeds the previous ciphertext block back into the block cipher as input.  
    > Treats the block cipher as a self-synchronizing stream cipher.
- OFB (Output Feedback mode)
    > Treats the block cipher as a synchronous stream cipher.  
    > Generates a keystream that is XORed with plaintext blocks to produce ciphertext.
- CTR (Counter (CTR) mode)
    > Treats the block cipher as a synchronous stream cipher.  
    > Generates keystream blocks by encrypting a value called the "counter".

## References

- [FIPS 197: Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation (Confidentiality)](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST SP 800-38C: Recommendation for Block Cipher Modes of Operation: the CCM Mode](https://csrc.nist.gov/pubs/sp/800/38/c/final)
- [Microsoft Learn: System.Security.Cryptography.Aes class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes)
