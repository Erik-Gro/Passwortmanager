#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_hash_function(void) {
    const char *pwd1 = "secret";
    uint64_t h1 = crypto_hash((const uint8_t *)pwd1, strlen(pwd1));

    const char *pwd2 = "secret";
    uint64_t h2 = crypto_hash((const uint8_t *)pwd2, strlen(pwd2));

    const char *pwd3 = "Secret";
    uint64_t h3 = crypto_hash((const uint8_t *)pwd3, strlen(pwd3));

    /* Same input must produce exact same 64-bit hash */
    assert(h1 == h2);
    /* Single bit change produces completely different hash */
    assert(h1 != h3);
    printf("[PASS] Hash verification test (Mersenne M61)\n");
}

void test_encryption_roundtrip(void) {
    const char *master_pwd = "SuperMasterPassword123!";
    const char *plaintext  = "GitHub\tjohn_doe\tCorrectHorseBatteryStaple\tjohn@example.com\thttps://github.com\t2FA enabled";
    size_t pt_len = strlen(plaintext);
    size_t pwd_len = strlen(master_pwd);

    uint8_t ciphertext[512];
    uint8_t decrypted[512];

    crypto_encrypt((const uint8_t *)plaintext, pt_len, (const uint8_t *)master_pwd, pwd_len, ciphertext);

    /* Ciphertext must not match plaintext */
    assert(memcmp(plaintext, ciphertext, pt_len) != 0);

    crypto_decrypt(ciphertext, pt_len, (const uint8_t *)master_pwd, pwd_len, decrypted);
    decrypted[pt_len] = '\0';

    /* Decrypted must exactly match original plaintext */
    assert(strcmp(plaintext, (char *)decrypted) == 0);
    printf("[PASS] Symmetric BBS encryption/decryption roundtrip\n");
}

void test_tampered_password_fails(void) {
    const char *correct_pwd = "ValidPassword";
    const char *wrong_pwd   = "WrongPassword";
    const char *plaintext   = "Banking\tadmin\tSecretPin99\t\t\t";
    size_t pt_len = strlen(plaintext);

    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    crypto_encrypt((const uint8_t *)plaintext, pt_len, (const uint8_t *)correct_pwd, strlen(correct_pwd), ciphertext);
    crypto_decrypt(ciphertext, pt_len, (const uint8_t *)wrong_pwd, strlen(wrong_pwd), decrypted);
    decrypted[pt_len] = '\0';

    /* Decryption with wrong password MUST produce garbage */
    assert(strcmp(plaintext, (char *)decrypted) != 0);
    printf("[PASS] Wrong password rejection test\n");
}

int main(void) {
    printf("=========================================\n");
    printf("   RUNNING CRYPTOGRAPHY TEST SUITE       \n");
    printf("=========================================\n");
    test_hash_function();
    test_encryption_roundtrip();
    test_tampered_password_fails();
    printf("\nAll 3 test suites passed successfully!\n");
    return 0;
}
