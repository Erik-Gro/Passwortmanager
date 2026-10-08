#define _POSIX_C_SOURCE 200809L

#include "db.h"
#include "entry.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_database_roundtrip_and_corruption_handling(void) {
    char filename[] = "/tmp/password_manager_test_XXXXXX";
    int fd = mkstemp(filename);
    assert(fd >= 0);
    close(fd);
    assert(unlink(filename) == 0);

    EntryList original;
    entry_list_init(&original);
    PasswordEntry *expected = entry_create("Mail", "alice", "secret", "",
                                           "https://example.test", "note");
    assert(expected);
    entry_list_append(&original, expected);
    assert(db_save(filename, "master-password", &original));

    struct stat file_stat;
    assert(stat(filename, &file_stat) == 0);
    assert((file_stat.st_mode & 0777) == 0600);

    EntryList loaded;
    entry_list_init(&loaded);
    assert(db_load(filename, "master-password", &loaded));
    assert(loaded.count == 1);
    assert(strcmp(loaded.head->name, expected->name) == 0);
    assert(strcmp(loaded.head->username, expected->username) == 0);
    assert(strcmp(loaded.head->password, expected->password) == 0);
    assert(strcmp(loaded.head->email, expected->email) == 0);
    assert(strcmp(loaded.head->url, expected->url) == 0);
    assert(strcmp(loaded.head->comment, expected->comment) == 0);

    EntryList wrong_password;
    entry_list_init(&wrong_password);
    assert(!db_load(filename, "wrong-password", &wrong_password));
    assert(wrong_password.count == 0);

    FILE *fp = fopen(filename, "rb");
    assert(fp);
    assert(fseek(fp, 0, SEEK_END) == 0);
    long file_size = ftell(fp);
    assert(file_size > 0);
    rewind(fp);
    unsigned char *contents = malloc((size_t)file_size);
    assert(contents);
    assert(fread(contents, 1, (size_t)file_size, fp) == (size_t)file_size);
    assert(fclose(fp) == 0);

    size_t first_line_end = 0;
    while (first_line_end < (size_t)file_size && contents[first_line_end] != '\n') {
        first_line_end++;
    }
    assert(first_line_end < (size_t)file_size);

    fp = fopen(filename, "wb");
    assert(fp);
    assert(fwrite(contents, 1, first_line_end, fp) == first_line_end);
    assert(fputc('\0', fp) != EOF);
    assert(fwrite(contents + first_line_end, 1,
                  (size_t)file_size - first_line_end, fp) ==
           (size_t)file_size - first_line_end);
    assert(fclose(fp) == 0);
    free(contents);

    EntryList embedded_nul;
    entry_list_init(&embedded_nul);
    assert(!db_load(filename, "master-password", &embedded_nul));
    assert(embedded_nul.count == 0);
    entry_list_free(&embedded_nul);

    assert(db_save(filename, "master-password", &original));

    fp = fopen(filename, "a");
    assert(fp);
    assert(fputs("not-hex\n", fp) >= 0);
    assert(fclose(fp) == 0);

    EntryList unchanged;
    entry_list_init(&unchanged);
    PasswordEntry *existing = entry_create("Existing", "bob", "keep", NULL, NULL, NULL);
    assert(existing);
    entry_list_append(&unchanged, existing);
    assert(!db_load(filename, "master-password", &unchanged));
    assert(unchanged.count == 1);
    assert(strcmp(unchanged.head->name, "Existing") == 0);

    entry_list_free(&unchanged);
    entry_list_free(&wrong_password);
    entry_list_free(&loaded);
    entry_list_free(&original);
    assert(unlink(filename) == 0);
}

int main(void) {
    test_database_roundtrip_and_corruption_handling();
    puts("Database tests passed.");
    return 0;
}
