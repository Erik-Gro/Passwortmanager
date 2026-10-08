#include "entry.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_entry_roundtrip(void) {
    PasswordEntry *entry = entry_create("Mail", "alice", "secret", "",
                                        "https://example.test", "note");
    assert(entry);

    char *serialized = entry_to_tab_string(entry);
    assert(serialized);
    assert(strcmp(serialized, "Mail\talice\tsecret\t\thttps://example.test\tnote") == 0);

    PasswordEntry *parsed = entry_from_tab_string(serialized);
    assert(parsed);
    assert(strcmp(parsed->name, entry->name) == 0);
    assert(strcmp(parsed->username, entry->username) == 0);
    assert(strcmp(parsed->password, entry->password) == 0);
    assert(strcmp(parsed->email, entry->email) == 0);
    assert(strcmp(parsed->url, entry->url) == 0);
    assert(strcmp(parsed->comment, entry->comment) == 0);

    free(serialized);
    entry_free(parsed);
    entry_free(entry);
}

static void test_invalid_entries_are_rejected(void) {
    assert(entry_create("", "alice", "secret", NULL, NULL, NULL) == NULL);
    assert(entry_create("Mail", "alice", "", NULL, NULL, NULL) == NULL);
    assert(entry_create("Bad\tName", "alice", "secret", NULL, NULL, NULL) == NULL);
    assert(entry_create("Mail", "alice", "secret", NULL, NULL, "line\nbreak") == NULL);

    assert(entry_from_tab_string("Mail\talice\tsecret\t\turl") == NULL);
    assert(entry_from_tab_string("Mail\talice\tsecret\t\turl\tnote\textra") == NULL);
    assert(entry_from_tab_string("\talice\tsecret\t\turl\tnote") == NULL);
}

static void test_list_operations(void) {
    EntryList list;
    entry_list_init(&list);

    PasswordEntry *first = entry_create("First", "alice", "one", NULL, NULL, NULL);
    PasswordEntry *second = entry_create("Second", "bob", "two", NULL, NULL, NULL);
    assert(first && second);
    entry_list_append(&list, first);
    entry_list_append(&list, second);

    assert(list.count == 2);
    assert(entry_list_get(&list, 1) == first);
    assert(entry_list_has_name(&list, "Second"));
    PasswordEntry *detached = entry_list_detach(&list, 1);
    assert(detached == first);
    assert(entry_list_get(&list, 1) == second);
    entry_list_insert(&list, 1, detached);
    assert(entry_list_get(&list, 1) == first);
    assert(entry_list_delete(&list, 1));
    assert(!entry_list_delete(&list, 2));

    entry_list_free(&list);
    assert(list.count == 0 && list.head == NULL);
}

int main(void) {
    test_entry_roundtrip();
    test_invalid_entries_are_rejected();
    test_list_operations();
    puts("Entry tests passed.");
    return 0;
}
