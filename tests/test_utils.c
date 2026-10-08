#define _POSIX_C_SOURCE 200809L

#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *redirect_stdin(const void *data, size_t length, int *saved_stdin) {
    FILE *input = tmpfile();
    assert(input);
    assert(fwrite(data, 1, length, input) == length);
    rewind(input);

    *saved_stdin = dup(STDIN_FILENO);
    assert(*saved_stdin >= 0);
    assert(dup2(fileno(input), STDIN_FILENO) >= 0);
    clearerr(stdin);
    return input;
}

static void restore_stdin(FILE *input, int saved_stdin) {
    assert(dup2(saved_stdin, STDIN_FILENO) >= 0);
    close(saved_stdin);
    fclose(input);
    clearerr(stdin);
}

static void test_hex_conversion(void) {
    const uint8_t input[] = { 0x00, 0x10, 0x7f, 0xff };
    char *hex = bytes_to_hex(input, sizeof(input));
    assert(hex);
    assert(strcmp(hex, "00107fff") == 0);

    size_t output_len = 0;
    uint8_t *output = hex_to_bytes(hex, &output_len);
    assert(output && output_len == sizeof(input));
    assert(memcmp(input, output, sizeof(input)) == 0);

    free(output);
    free(hex);
    assert(hex_to_bytes("123", &output_len) == NULL);
    assert(hex_to_bytes("zz", &output_len) == NULL);
    assert(hex_to_bytes("", &output_len) == NULL);
    assert(output_len == 0);
}

static void test_random_password_generation(void) {
    char *password = generate_random_password(64);
    assert(password && strlen(password) == 64);

    for (size_t i = 0; password[i]; i++) {
        assert((password[i] >= 'a' && password[i] <= 'z') ||
               (password[i] >= 'A' && password[i] <= 'Z') ||
               (password[i] >= '0' && password[i] <= '9') ||
               strchr("!@#$%^&*()-_=+", password[i]) != NULL);
    }
    free(password);
}

static void test_line_input_boundaries(void) {
    char buffer[5];
    int saved_stdin;
    FILE *input = redirect_stdin("abcd\nnext\n", 10, &saved_stdin);
    assert(read_line(buffer, sizeof(buffer)));
    assert(strcmp(buffer, "abcd") == 0);
    assert(read_line(buffer, sizeof(buffer)));
    assert(strcmp(buffer, "next") == 0);
    restore_stdin(input, saved_stdin);

    input = redirect_stdin("abcde\nok\n", 9, &saved_stdin);
    assert(!read_line(buffer, sizeof(buffer)));
    assert(read_line(buffer, sizeof(buffer)));
    assert(strcmp(buffer, "ok") == 0);
    restore_stdin(input, saved_stdin);

    const char nul_input[] = { 'x', '\0', 'y', '\n', 'z', '\n' };
    input = redirect_stdin(nul_input, sizeof(nul_input), &saved_stdin);
    assert(!read_line(buffer, sizeof(buffer)));
    assert(read_line(buffer, sizeof(buffer)));
    assert(strcmp(buffer, "z") == 0);
    restore_stdin(input, saved_stdin);
}

int main(void) {
    test_hex_conversion();
    test_random_password_generation();
    test_line_input_boundaries();
    puts("Utility tests passed.");
    return 0;
}
