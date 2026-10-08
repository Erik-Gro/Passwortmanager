#include "entry.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1);
    if (copy) {
        memcpy(copy, s, len + 1);
    }
    return copy;
}

static bool field_is_valid(const char *field) {
    if (!field) return false;
    for (const char *p = field; *p; p++) {
        if (*p == '\t' || *p == '\r' || *p == '\n') return false;
    }
    return true;
}

void entry_list_init(EntryList *list) {
    list->head = NULL;
    list->count = 0;
}

PasswordEntry *entry_create(const char *name, const char *username, const char *password,
                            const char *email, const char *url, const char *comment) {
    email = email ? email : "";
    url = url ? url : "";
    comment = comment ? comment : "";
    if (!name || !*name || !username || !*username || !password || !*password ||
        !field_is_valid(name) || !field_is_valid(username) || !field_is_valid(password) ||
        !field_is_valid(email) || !field_is_valid(url) || !field_is_valid(comment)) {
        return NULL;
    }

    PasswordEntry *e = (PasswordEntry *)malloc(sizeof(PasswordEntry));
    if (!e) return NULL;

    e->name = NULL;
    e->username = NULL;
    e->password = NULL;
    e->email = NULL;
    e->url = NULL;
    e->comment = NULL;
    e->next = NULL;

    e->name     = safe_strdup(name);
    e->username = safe_strdup(username);
    e->password = safe_strdup(password);
    e->email    = safe_strdup(email);
    e->url      = safe_strdup(url);
    e->comment  = safe_strdup(comment);
    if (!e->name || !e->username || !e->password || !e->email || !e->url || !e->comment) {
        entry_free(e);
        return NULL;
    }
    return e;
}

void entry_free(PasswordEntry *entry) {
    if (!entry) return;
    free(entry->name);
    free(entry->username);
    free(entry->password);
    free(entry->email);
    free(entry->url);
    free(entry->comment);
    free(entry);
}

void entry_list_free(EntryList *list) {
    PasswordEntry *curr = list->head;
    while (curr) {
        PasswordEntry *next = curr->next;
        entry_free(curr);
        curr = next;
    }
    list->head = NULL;
    list->count = 0;
}

void entry_list_append(EntryList *list, PasswordEntry *entry) {
    if (!list || !entry) return;
    if (!list->head) {
        list->head = entry;
    } else {
        PasswordEntry *curr = list->head;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = entry;
    }
    list->count++;
}

bool entry_list_delete(EntryList *list, size_t index_1based) {
    PasswordEntry *entry = entry_list_detach(list, index_1based);
    if (!entry) return false;
    entry_free(entry);
    return true;
}

PasswordEntry *entry_list_detach(EntryList *list, size_t index_1based) {
    if (!list || index_1based == 0 || index_1based > list->count) return NULL;

    PasswordEntry *prev = NULL;
    PasswordEntry *curr = list->head;

    for (size_t i = 1; i < index_1based; i++) {
        prev = curr;
        curr = curr->next;
    }

    if (!prev) {
        list->head = curr->next;
    } else {
        prev->next = curr->next;
    }

    curr->next = NULL;
    list->count--;
    return curr;
}

void entry_list_insert(EntryList *list, size_t index_1based, PasswordEntry *entry) {
    if (!list || !entry || index_1based == 0 || index_1based > list->count + 1) return;

    if (index_1based == 1) {
        entry->next = list->head;
        list->head = entry;
    } else {
        PasswordEntry *prev = entry_list_get(list, index_1based - 1);
        entry->next = prev->next;
        prev->next = entry;
    }
    list->count++;
}

PasswordEntry *entry_list_get(const EntryList *list, size_t index_1based) {
    if (!list || index_1based == 0 || index_1based > list->count) return NULL;
    PasswordEntry *curr = list->head;
    for (size_t i = 1; i < index_1based; i++) {
        curr = curr->next;
    }
    return curr;
}

bool entry_list_has_name(const EntryList *list, const char *name) {
    if (!list || !name) return false;
    PasswordEntry *curr = list->head;
    while (curr) {
        if (strcmp(curr->name, name) == 0) return true;
        curr = curr->next;
    }
    return false;
}

char *entry_to_tab_string(const PasswordEntry *entry) {
    if (!entry) return NULL;
    const char *fields[] = { entry->name, entry->username, entry->password,
                             entry->email, entry->url, entry->comment };
    size_t len = 6;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!field_is_valid(fields[i])) return NULL;
        size_t field_len = strlen(fields[i]);
        if (field_len > SIZE_MAX - len) return NULL;
        len += field_len;
    }

    char *buf = (char *)malloc(len);
    if (!buf) return NULL;

    snprintf(buf, len, "%s\t%s\t%s\t%s\t%s\t%s",
             entry->name, entry->username, entry->password,
             entry->email, entry->url, entry->comment);
    return buf;
}

PasswordEntry *entry_from_tab_string(const char *tab_line) {
    if (!tab_line) return NULL;

    char *dup = safe_strdup(tab_line);
    if (!dup) return NULL;
    char *fields[6] = { "", "", "", "", "", "" };
    size_t field_count = 1;
    fields[0] = dup;

    for (char *p = dup; *p; p++) {
        if (*p == '\t') {
            if (field_count == sizeof(fields) / sizeof(fields[0])) {
                free(dup);
                return NULL;
            }
            *p = '\0';
            fields[field_count++] = p + 1;
        }
    }
    if (field_count != sizeof(fields) / sizeof(fields[0])) {
        free(dup);
        return NULL;
    }

    PasswordEntry *e = entry_create(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]);
    free(dup);
    return e;
}
