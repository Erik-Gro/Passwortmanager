#define _POSIX_C_SOURCE 200809L

#include "db.h"
#include "entry.h"
#include "crypto.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#define DB_LINE_CAPACITY 4096

static bool db_read_line(FILE *fp, char *line, size_t capacity, bool *has_line) {
    size_t len = 0;
    bool too_long = false;
    bool contains_nul = false;
    int ch;

    *has_line = false;
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        if (ch == '\0') {
            contains_nul = true;
            continue;
        }
        if (len + 1 < capacity) {
            line[len++] = (char)ch;
        } else {
            too_long = true;
        }
    }
    if (ferror(fp)) return false;
    if (ch == EOF && len == 0 && !too_long && !contains_nul) return true;
    if (len > 0 && line[len - 1] == '\r') len--;
    line[len] = '\0';
    if (too_long || contains_nul) return false;
    *has_line = true;
    return true;
}

static bool write_encrypted_line(FILE *fp, const uint8_t *plaintext, size_t length,
                                 const char *master_pwd, size_t pwd_len) {
    uint8_t *ciphertext = malloc(length);
    if (!ciphertext) return false;

    crypto_encrypt(plaintext, length, (const uint8_t *)master_pwd, pwd_len, ciphertext);
    char *hex = bytes_to_hex(ciphertext, length);
    free(ciphertext);
    if (!hex) return false;

    bool success = fputs(hex, fp) != EOF && fputc('\n', fp) != EOF;
    free(hex);
    return success;
}

bool db_exists(const char *filename) {
    if (!filename) return false;
    FILE *fp = fopen(filename, "r");
    if (!fp) return false;
    fclose(fp);
    return true;
}

bool db_load(const char *filename, const char *master_pwd, EntryList *list) {
    if (!filename || !master_pwd || !*master_pwd || !list) return false;

    FILE *fp = fopen(filename, "r");
    if (!fp) return false;

    EntryList loaded;
    entry_list_init(&loaded);
    char line_buf[DB_LINE_CAPACITY];
    bool success = false;
    bool has_line;

    if (!db_read_line(fp, line_buf, sizeof(line_buf), &has_line) || !has_line) {
        goto cleanup;
    }

    size_t token_len = 0;
    uint8_t *token = hex_to_bytes(line_buf, &token_len);
    size_t pwd_len = strlen(master_pwd);
    if (!token || token_len != pwd_len) {
        free(token);
        goto cleanup;
    }

    uint8_t *decrypted_token = malloc(token_len);
    if (!decrypted_token) {
        free(token);
        goto cleanup;
    }
    crypto_decrypt(token, token_len, (const uint8_t *)master_pwd, pwd_len, decrypted_token);
    free(token);
    bool password_matches = memcmp(decrypted_token, master_pwd, pwd_len) == 0;
    free(decrypted_token);
    if (!password_matches) goto cleanup;

    for (;;) {
        if (!db_read_line(fp, line_buf, sizeof(line_buf), &has_line)) goto cleanup;
        if (!has_line) break;

        size_t ciphertext_len = 0;
        uint8_t *ciphertext = hex_to_bytes(line_buf, &ciphertext_len);
        if (!ciphertext) goto cleanup;

        uint8_t *plaintext = malloc(ciphertext_len + 1);
        if (!plaintext) {
            free(ciphertext);
            goto cleanup;
        }
        crypto_decrypt(ciphertext, ciphertext_len, (const uint8_t *)master_pwd,
                       pwd_len, plaintext);
        plaintext[ciphertext_len] = '\0';
        free(ciphertext);

        PasswordEntry *entry = entry_from_tab_string((const char *)plaintext);
        free(plaintext);
        if (!entry) goto cleanup;
        entry_list_append(&loaded, entry);
    }

    while (loaded.head) {
        PasswordEntry *entry = loaded.head;
        loaded.head = entry->next;
        entry->next = NULL;
        loaded.count--;
        entry_list_append(list, entry);
    }
    success = true;

cleanup:
    fclose(fp);
    entry_list_free(&loaded);
    return success;
}

bool db_save(const char *filename, const char *master_pwd, const EntryList *list) {
    if (!filename || !master_pwd || !*master_pwd || !list) return false;

    size_t filename_len = strlen(filename);
    static const char suffix[] = ".tmp.XXXXXX";
    if (filename_len > SIZE_MAX - sizeof(suffix)) return false;

    char *tmp_filename = malloc(filename_len + sizeof(suffix));
    if (!tmp_filename) return false;
    memcpy(tmp_filename, filename, filename_len);
    memcpy(tmp_filename + filename_len, suffix, sizeof(suffix));

    int fd = mkstemp(tmp_filename);
    if (fd == -1) {
        free(tmp_filename);
        return false;
    }
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        unlink(tmp_filename);
        free(tmp_filename);
        return false;
    }

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        unlink(tmp_filename);
        free(tmp_filename);
        return false;
    }

    size_t pwd_len = strlen(master_pwd);
    bool success = write_encrypted_line(fp, (const uint8_t *)master_pwd,
                                        pwd_len, master_pwd, pwd_len);

    for (const PasswordEntry *entry = list->head; success && entry; entry = entry->next) {
        char *serialized = entry_to_tab_string(entry);
        if (!serialized) {
            success = false;
            break;
        }
        success = write_encrypted_line(fp, (const uint8_t *)serialized,
                                       strlen(serialized), master_pwd, pwd_len);
        free(serialized);
    }

    if (fclose(fp) != 0) success = false;
    if (success && rename(tmp_filename, filename) != 0) success = false;
    if (!success) unlink(tmp_filename);
    free(tmp_filename);
    return success;
}
