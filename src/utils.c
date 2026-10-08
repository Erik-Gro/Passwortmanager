#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

bool read_line(char *buffer, size_t max_len) {
    if (!buffer || max_len == 0) {
        return false;
    }

    size_t len = 0;
    bool too_long = false;
    bool contains_nul = false;
    int ch;
    while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
        if (ch == '\0') {
            contains_nul = true;
            continue;
        }
        if (len + 1 < max_len) {
            buffer[len++] = (char)ch;
        } else {
            too_long = true;
        }
    }

    if (ferror(stdin)) {
        buffer[0] = '\0';
        return false;
    }

    if (ch == EOF && len == 0 && !too_long && !contains_nul) return false;
    if (len > 0 && buffer[len - 1] == '\r') len--;
    if (too_long || contains_nul) {
        buffer[0] = '\0';
        fprintf(stderr, "Input is invalid or too long; the rest of the line was discarded.\n");
        return false;
    }
    buffer[len] = '\0';
    return true;
}

char *bytes_to_hex(const uint8_t *bytes, size_t len) {
    if ((!bytes && len > 0) || len > (SIZE_MAX - 1) / 2) {
        return NULL;
    }
    char *hex = (char *)malloc(len * 2 + 1);
    if (!hex) return NULL;

    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = hex_digits[(bytes[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_digits[bytes[i] & 0x0F];
    }
    hex[len * 2] = '\0';
    return hex;
}

static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

uint8_t *hex_to_bytes(const char *hex_str, size_t *out_len) {
    if (!hex_str || !out_len) return NULL;
    *out_len = 0;
    size_t hex_len = strlen(hex_str);
    if (hex_len == 0 || hex_len % 2 != 0) return NULL;

    size_t byte_len = hex_len / 2;
    uint8_t *bytes = (uint8_t *)malloc(byte_len);
    if (!bytes) return NULL;

    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_char_val(hex_str[i * 2]);
        int low  = hex_char_val(hex_str[i * 2 + 1]);
        if (high < 0 || low < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (uint8_t)((high << 4) | low);
    }

    *out_len = byte_len;
    return bytes;
}

char *generate_random_password(size_t length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
    const size_t charset_size = sizeof(charset) - 1;

    if (length == 0) {
        char *pass = (char *)malloc(1);
        if (!pass) return NULL;
        pass[0] = '\0';
        return pass;
    }
    if (length == SIZE_MAX) return NULL;

    FILE *rand_file = fopen("/dev/urandom", "rb");
    if (!rand_file) {
        return NULL;
    }

    char *pass = (char *)malloc(length + 1);
    if (!pass) {
        fclose(rand_file);
        return NULL;
    }

    const size_t byte_range = 256;
    const size_t accepted_range = byte_range - (byte_range % charset_size);
    for (size_t i = 0; i < length; i++) {
        unsigned char random_byte;
        do {
            if (fread(&random_byte, 1, 1, rand_file) != 1) {
                free(pass);
                fclose(rand_file);
                return NULL;
            }
        } while ((size_t)random_byte >= accepted_range);
        pass[i] = charset[random_byte % charset_size];
    }
    pass[length] = '\0';
    fclose(rand_file);
    return pass;
}
