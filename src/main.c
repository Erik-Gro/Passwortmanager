#include "crypto.h"
#include "entry.h"
#include "db.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

static void print_banner(void) {
    printf("=========================================\n");
    printf("             PASSWORD MANAGER            \n");
    printf("=========================================\n\n");
}

static void print_menu(void) {
    printf("\nMenu:\n");
    printf("  l       - list all entries\n");
    printf("  s <nr>  - show entry details\n");
    printf("  a       - add a new entry\n");
    printf("  d <nr>  - delete entry\n");
    printf("  p       - change master password\n");
    printf("  q       - quit\n");
    printf("> ");
}

static bool parse_entry_number(const char *arg, size_t *number) {
    char *end = NULL;
    errno = 0;
    unsigned long long parsed_nr = strtoull(arg, &end, 10);
    if (errno == ERANGE || end == arg || *end != '\0' || arg[0] < '0' ||
        arg[0] > '9' || parsed_nr == 0 || parsed_nr > SIZE_MAX) {
        printf("Error: Entry number must be a positive integer.\n");
        return false;
    }

    *number = (size_t)parsed_nr;
    return true;
}

static void handle_list(const EntryList *list) {
    if (list->count == 0) {
        printf("Database is empty.\n");
        return;
    }
    printf("\n--- Stored Entries (%zu) ---\n", list->count);
    PasswordEntry *curr = list->head;
    size_t idx = 1;
    while (curr) {
        printf("%3zu) %s\n", idx++, curr->name);
        curr = curr->next;
    }
}

static void handle_show(const EntryList *list, const char *arg) {
    if (!arg || *arg == '\0') {
        printf("Usage: s <nr>\n");
        return;
    }
    size_t nr;
    if (!parse_entry_number(arg, &nr)) return;

    PasswordEntry *e = entry_list_get(list, nr);
    if (!e) {
        printf("Error: Entry %zu does not exist.\n", nr);
        return;
    }

    printf("\n--- Entry #%zu: %s ---\n", nr, e->name);
    printf("  Username : %s\n", e->username);
    printf("  Password : %s\n", e->password);
    printf("  E-Mail   : %s\n", e->email[0] ? e->email : "(none)");
    printf("  URL      : %s\n", e->url[0] ? e->url : "(none)");
    printf("  Comment  : %s\n", e->comment[0] ? e->comment : "(none)");
}

static void handle_add(EntryList *list, const char *master_pwd) {
    char name[256], user[256], pass[256], email[256], url[256], comment[256];

    printf("\n[Add New Entry]\n");
    printf("Name: ");
    if (!read_line(name, sizeof(name)) || strlen(name) == 0) {
        printf("Name cannot be empty.\n");
        return;
    }

    if (entry_list_has_name(list, name)) {
        printf("Error: An entry named '%s' already exists (Name must be unique).\n", name);
        return;
    }

    printf("Username: ");
    if (!read_line(user, sizeof(user)) || strlen(user) == 0) {
        printf("Username cannot be empty.\n");
        return;
    }

    printf("Password (leave blank to auto-generate): ");
    if (!read_line(pass, sizeof(pass))) return;
    if (strlen(pass) == 0) {
        char *gen = generate_random_password(16);
        if (gen) {
            snprintf(pass, sizeof(pass), "%s", gen);
            printf("Generated Password: %s\n", pass);
            free(gen);
        } else {
            printf("Error: Failed to generate a secure password.\n");
            return;
        }
    }

    printf("E-Mail (optional): ");
    if (!read_line(email, sizeof(email))) return;

    printf("URL (optional): ");
    if (!read_line(url, sizeof(url))) return;

    printf("Comment (optional): ");
    if (!read_line(comment, sizeof(comment))) return;

    PasswordEntry *new_entry = entry_create(name, user, pass, email, url, comment);
    if (!new_entry) {
        printf("Error: Could not create entry. Fields must not contain tabs or newlines.\n");
        return;
    }
    entry_list_append(list, new_entry);

    if (db_save(DB_DEFAULT_FILE, master_pwd, list)) {
        printf("Entry '%s' successfully added and database saved.\n", name);
    } else {
        entry_list_delete(list, list->count);
        printf("Error: Failed to save database to disk!\n");
    }
}

static void handle_delete(EntryList *list, const char *arg, const char *master_pwd) {
    if (!arg || *arg == '\0') {
        printf("Usage: d <nr>\n");
        return;
    }
    size_t nr;
    if (!parse_entry_number(arg, &nr)) return;

    PasswordEntry *removed = entry_list_detach(list, nr);
    if (!removed) {
        printf("Error: Could not delete entry %zu (invalid index).\n", nr);
        return;
    }

    if (db_save(DB_DEFAULT_FILE, master_pwd, list)) {
        entry_free(removed);
        printf("Entry #%zu deleted and database saved.\n", nr);
    } else {
        entry_list_insert(list, nr, removed);
        printf("Error: Failed to save changes.\n");
    }
}

static bool handle_change_password(EntryList *list, char *master_pwd, size_t max_pwd_len) {
    char p1[256], p2[256];
    printf("\nEnter new Master Password: ");
    if (!read_line(p1, sizeof(p1)) || strlen(p1) == 0) {
        printf("Password cannot be empty.\n");
        return false;
    }

    printf("Confirm new Master Password: ");
    if (!read_line(p2, sizeof(p2))) return false;

    if (strcmp(p1, p2) != 0) {
        printf("Error: Passwords do not match. Aborting.\n");
        return false;
    }

    if (db_save(DB_DEFAULT_FILE, p1, list)) {
        snprintf(master_pwd, max_pwd_len, "%s", p1);
        printf("Master Password successfully updated and database re-encrypted!\n");
        return true;
    } else {
        printf("Error writing re-encrypted database.\n");
        return false;
    }
}

static bool initialize_database(EntryList *list, char *master_pwd, size_t max_pwd_len) {
    if (db_exists(DB_DEFAULT_FILE)) {

        printf("Found existing database '%s'.\n", DB_DEFAULT_FILE);
        printf("Enter Master Password: ");
        if (!read_line(master_pwd, max_pwd_len) || strlen(master_pwd) == 0) {
            fprintf(stderr, "Password cannot be empty.\n");
            return false;
        }

        if (!db_load(DB_DEFAULT_FILE, master_pwd, list)) {
            fprintf(stderr, "\nACCESS DENIED: Incorrect password or invalid database file.\n");
            return false;
        }
        printf("Access granted! Loaded %zu entries.\n", list->count);
    } else {
  
        printf("No existing database found. Creating a new one.\n");
        char confirm[256];

        while (1) {
            printf("Define Master Password: ");
            if (!read_line(master_pwd, max_pwd_len) || strlen(master_pwd) == 0) {
                if (feof(stdin)) return false;
                printf("Password cannot be empty.\n");
                continue;
            }

            printf("Verify Master Password: ");
            if (!read_line(confirm, sizeof(confirm))) return false;

            if (strcmp(master_pwd, confirm) == 0) {
                break;
            }
            printf("Passwords do not match! Please try again.\n\n");
        }

        if (!db_save(DB_DEFAULT_FILE, master_pwd, list)) {
            fprintf(stderr, "Error creating database file.\n");
            return false;
        }
        printf("Database initialized successfully.\n");
    }

    return true;
}

static void run_interactive_loop(EntryList *list, char *master_pwd,
                                 size_t max_pwd_len) {
    char input[512];

    while (true) {
        print_menu();
        if (!read_line(input, sizeof(input))) break;

        char *cmd = input;
        while (*cmd == ' ') cmd++;

        if (*cmd == '\0') continue;

        if (cmd[0] == 'l' && (cmd[1] == '\0' || cmd[1] == ' ')) {
            handle_list(list);
        } else if (cmd[0] == 's' && (cmd[1] == '\0' || cmd[1] == ' ')) {
            char *arg = cmd + 1;
            while (*arg == ' ') arg++;
            handle_show(list, arg);
        } else if (strcmp(cmd, "a") == 0) {
            handle_add(list, master_pwd);
        } else if (cmd[0] == 'd' && (cmd[1] == '\0' || cmd[1] == ' ')) {
            char *arg = cmd + 1;
            while (*arg == ' ') arg++;
            handle_delete(list, arg, master_pwd);
        } else if (strcmp(cmd, "p") == 0) {
            handle_change_password(list, master_pwd, max_pwd_len);
        } else if (strcmp(cmd, "q") == 0) {
            printf("Exiting. Cleaning up memory.\n");
            break;
        } else {
            printf("Unknown command '%s'. Valid: l, s <nr>, a, d <nr>, p, q\n", cmd);
        }
    }
}

int main(void) {
    print_banner();

    char master_pwd[256];
    EntryList list;
    entry_list_init(&list);

    if (!initialize_database(&list, master_pwd, sizeof(master_pwd))) {
        entry_list_free(&list);
        return 1;
    }

    run_interactive_loop(&list, master_pwd, sizeof(master_pwd));
    entry_list_free(&list);
    return 0;
}
