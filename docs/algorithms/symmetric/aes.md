# AES (Advanced Encryption Standard)

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

<!-- spell-checker:words CCMP -->

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

<!-- spell-checker:words Chiper -->
