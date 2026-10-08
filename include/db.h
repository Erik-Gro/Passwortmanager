#ifndef DB_H
#define DB_H

#include "entry.h"
#include <stdbool.h>

#define DB_DEFAULT_FILE "passwords.db"

/* Checks whether the database file exists on disk */
bool db_exists(const char *filename);

/* Loads and decrypts database; returns false if master password check fails */
bool db_load(const char *filename, const char *master_pwd, EntryList *list);

/* Atomically saves encrypted database using a temporary file and rename() */
bool db_save(const char *filename, const char *master_pwd, const EntryList *list);

#endif /* DB_H */
