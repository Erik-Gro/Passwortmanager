#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* p = 65539 */
#define BBS_PRIME_P 65539ULL
/* q = 65531 */
#define BBS_PRIME_Q 65531ULL
#define BBS_MODULUS (BBS_PRIME_P * BBS_PRIME_Q) /* 4,294,836,209ULL */

/* 2^61 - 1 */
#define HASH_MODULUS ((1ULL << 61) - 1ULL) /* 2,305,843,009,213,693,951ULL */

/**
 * Computes the 64-bit hash of an arbitrary byte sequence according to:
 * h_{i+1} = (3 * h_i + m_i) mod (2^61 - 1)
 */
uint64_t crypto_hash(const uint8_t *bytes, size_t length);

/**
 * Initializes (or resets) the Blum-Blum-Shub PRNG with the seed.
 */
void bbs_init(uint64_t seed);

/**
 * Generates the next pseudorandom byte (assembling 8 consecutive LSB bits).
 */
uint8_t bbs_next_byte(void);

/**
 * Encrypts a plaintext byte buffer using the master password and BBS stream.
 */
void crypto_encrypt(const uint8_t *plaintext, size_t length,
                    const uint8_t *master_pwd, size_t pwd_len,
                    uint8_t *ciphertext);

/**
 * Decrypts a ciphertext byte buffer using the master password and BBS stream.
 */
void crypto_decrypt(const uint8_t *ciphertext, size_t length,
                    const uint8_t *master_pwd, size_t pwd_len,
                    uint8_t *plaintext);

#endif /* CRYPTO_H */
