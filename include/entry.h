#ifndef ENTRY_H
#define ENTRY_H

#include <stddef.h>
#include <stdbool.h>

/* Data model for a single decrypted record */
typedef struct PasswordEntry {
    char *name;         /* Unique entry title (mandatory) */
    char *username;     /* Username / login (mandatory) */
    char *password;     /* Secret password (mandatory) */
    char *email;        /* Email address (optional) */
    char *url;          /* Web link (optional) */
    char *comment;      /* Extra notes (optional) */

    struct PasswordEntry *next; /* Singly-linked list pointer */
} PasswordEntry;

/* Linked list container */
typedef struct {
    PasswordEntry *head;
    size_t count;
} EntryList;

void entry_list_init(EntryList *list);
void entry_list_free(EntryList *list);

PasswordEntry *entry_create(const char *name, const char *username, const char *password,
                            const char *email, const char *url, const char *comment);
void entry_free(PasswordEntry *entry);

void entry_list_append(EntryList *list, PasswordEntry *entry);
PasswordEntry *entry_list_detach(EntryList *list, size_t index_1based);
void entry_list_insert(EntryList *list, size_t index_1based, PasswordEntry *entry);
bool entry_list_delete(EntryList *list, size_t index_1based);
PasswordEntry *entry_list_get(const EntryList *list, size_t index_1based);
bool entry_list_has_name(const EntryList *list, const char *name);

/* Serializes fields into tab-delimited string (caller frees result) */
char *entry_to_tab_string(const PasswordEntry *entry);

/* Deserializes tab-delimited string into a new PasswordEntry struct */
PasswordEntry *entry_from_tab_string(const char *tab_line);

#endif /* ENTRY_H */
