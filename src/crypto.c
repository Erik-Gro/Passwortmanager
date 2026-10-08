#include "crypto.h"
#include <string.h>

static uint64_t g_bbs_seed = 0;
static uint64_t g_bbs_state = 0;

uint64_t crypto_hash(const uint8_t *bytes, size_t length) {
    if (!bytes && length != 0) {
        return 0;
    }

    uint64_t h = 0;
    for (size_t i = 0; i < length; i++) {
        h = (3ULL * h + (uint64_t)bytes[i]) % HASH_MODULUS;
    }
    return h;
}

void bbs_init(uint64_t seed) {
    g_bbs_seed = seed;

    uint64_t s = seed % BBS_MODULUS;
    if (s == 0) {
        s = 1;
    }

    /* x0 = s^2 mod N, as specified in the PDF assignment */
    g_bbs_state = (s * s) % BBS_MODULUS;
}

static uint8_t bbs_next_bit(void) {
    g_bbs_state = (g_bbs_state * g_bbs_state) % BBS_MODULUS;
    return (uint8_t)(g_bbs_state & 1ULL);
}

uint8_t bbs_next_byte(void) {
    uint8_t byte = 0;
    for (int bit_nr = 0; bit_nr < 8; bit_nr++) {
        uint8_t bit = bbs_next_bit();
        byte = (byte << 1) | bit;
    }
    return byte;
}

void crypto_encrypt(const uint8_t *plaintext, size_t length,
                    const uint8_t *master_pwd, size_t pwd_len,
                    uint8_t *ciphertext) {
    if (!plaintext || !master_pwd || !ciphertext || pwd_len == 0) {
        return;
    }

    uint64_t seed = crypto_hash(master_pwd, pwd_len);
    bbs_init(seed);

    for (size_t i = 0; i < length; i++) {
        size_t j = (size_t)bbs_next_byte() % pwd_len;
        ciphertext[i] = (uint8_t)(((uint32_t)master_pwd[j] + (uint32_t)plaintext[i]) % 256U);
    }

    bbs_init(seed);
}

void crypto_decrypt(const uint8_t *ciphertext, size_t length,
                    const uint8_t *master_pwd, size_t pwd_len,
                    uint8_t *plaintext) {
    if (!ciphertext || !master_pwd || !plaintext || pwd_len == 0) {
        return;
    }

    uint64_t seed = crypto_hash(master_pwd, pwd_len);
    bbs_init(seed);

    for (size_t i = 0; i < length; i++) {
        size_t j = (size_t)bbs_next_byte() % pwd_len;
        plaintext[i] = (uint8_t)((256U + (uint32_t)ciphertext[i] - (uint32_t)master_pwd[j]) % 256U);
    }

    bbs_init(seed);
}
