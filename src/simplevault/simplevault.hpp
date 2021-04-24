#pragma once

#include "../cli/constants.hpp"
#include <vector>

typedef unsigned char byte;

typedef struct Cell {
    char _service[MAX_SERVICE_N_USER_LEN + 1];
    char _username[MAX_SERVICE_N_USER_LEN + 1];
    char _password[MAX_PWD_LEN + 1];

} Cell;

typedef struct Vault {
    std::vector<Cell> cells;
    byte master_hash[MASTER_HASH_LEN + 1];
} Vault;
