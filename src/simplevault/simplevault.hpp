#pragma once

#include "../cli/constants.hpp"

typedef unsigned char byte;

typedef struct Cell {
    char _service[MAX_SERVICE_N_USER_LEN + 1];
    char _username[MAX_SERVICE_N_USER_LEN + 1];
    char _password[MAX_PWD_LEN + 1];

} Cell;

typedef struct Vault {
    int cell_count;
    Cell cells[VAULT_MAX];
    byte master_hash[MASTER_HASH_LEN + 1];
} Vault;