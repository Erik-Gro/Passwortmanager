#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Reads one complete line; returns false on EOF or if the line is too long. */
bool read_line(char *buffer, size_t max_len);

/* Hexadecimal encoding */
char *bytes_to_hex(const uint8_t *bytes, size_t len);
/* Hexadecimal decoding */
uint8_t *hex_to_bytes(const char *hex_str, size_t *out_len);

/* Random password generator */
char *generate_random_password(size_t length);

#endif /* UTILS_H */
