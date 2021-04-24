#include <string.h>
#include "enclave_t.h"

#include "sgx_tseal.h"
#include "sealing/sealing.h"
#include "../cli/constants.hpp"

int ecall_create_vault(const char* master_hash) {
    // check if vault already exists
    sgx_status_t is_vault_status;
    int is_vault_ret;
    is_vault_status = ocall_vault_exists(&is_vault_ret);
    if (is_vault_ret != RET_SUCCESS) {
        return ERR_VAULT_ALREADY_EXISTS;
    }

    // create new vault
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    memcpy(vault->master_hash, master_hash, MASTER_HASH_LEN);

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault);
    free(vault);
    if (store_ret != RET_SUCCESS) {
        return store_ret;
    }

    return RET_SUCCESS;
}

int ecall_list_vault(const char* master_hash) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault); //TODO: error handling
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }


    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }
    int retval = 0;
    for (unsigned int i = 0; i < vault->cells.size(); ++i) {
        ocall_print_credentials(&retval, vault->cells.at(i)._service, vault->cells.at(i)._username, NULL);   // TODO error check
    }

    free(vault);
    return RET_SUCCESS;
}

int ecall_change_master_password(const char* old_master_hash, const char* new_master_hash) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, old_master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }

    memcpy(vault->master_hash, new_master_hash, MASTER_HASH_LEN);

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault);
    if (store_ret != RET_SUCCESS) {
        return store_ret;
    }

    free(vault);
    return RET_SUCCESS;
}

int ecall_add_entry(const char* master_hash, const char* service, const char* username, const char* password) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }
    Cell* new_cell = new Cell();
    strncpy(new_cell->_service, service, MAX_SERVICE_N_USER_LEN);
    strncpy(new_cell->_username, username, MAX_SERVICE_N_USER_LEN);
    strncpy(new_cell->_password, password, MAX_PWD_LEN);
    vault->cells.push_back(*new_cell);

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault);
    free(vault);
    if (store_ret != RET_SUCCESS) {
        return store_ret;
    }

    return RET_SUCCESS;
}

int ecall_list_entry(const char* master_hash, const char* service) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }

    int retval = 0;
    for (unsigned i = 0; i < vault->cells.size(); ++i) {
        if (strncmp(service, vault->cells.at(i)._service, MAX_SERVICE_N_USER_LEN) == 0) {
            ocall_print_credentials(&retval, service, vault->cells.at(i)._username, vault->cells.at(i)._password);   // TODO error check
        }
    }

    free(vault);
    return RET_SUCCESS;
}

int ecall_change_entry(const char* master_hash, const char* service, const char* username, const char* password) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }

    bool found = false;
    for (unsigned i = 0; i < vault->cells.size(); ++i) {
        if (strncmp(service, vault->cells.at(i)._service, MAX_SERVICE_N_USER_LEN) == 0 && strncmp(username, vault->cells.at(i)._username, MAX_SERVICE_N_USER_LEN) == 0) {
            found = true;
            strncpy(vault->cells.at(i)._password, password, MAX_PWD_LEN);
        }
    }

    if (!found) {
        free(vault);
        return ERR_SERVICE_USERNAME_NOT_FOUND;
    }

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault);
    free(vault);
    if (store_ret != RET_SUCCESS) {
        return store_ret;
    }

    return RET_SUCCESS;
}

int ecall_remove_entry(const char* master_hash, const char* service, const char* username) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }
    
    // find and erase
    bool found = false;
    for (std::vector<Cell>::iterator it = vault->cells.begin(); it != vault->cells.end(); ++it) {
        if (strncmp(service, it->_service, MAX_SERVICE_N_USER_LEN) == 0 && strncmp(username, it->_username, MAX_SERVICE_N_USER_LEN) == 0) {
            it = vault->cells.erase(it);
        }
    }
    if (!found) {
        free(vault);
        return ERR_SERVICE_USERNAME_NOT_FOUND;
    }

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault);
    free(vault);
    if (store_ret != RET_SUCCESS) {
        return store_ret;
    }

    return RET_SUCCESS;
}

// seal and save vault to file
int ecall_store_vault(Vault* vault) {
    // seal vault
    sgx_status_t sealing_status;
    const size_t vault_size = vault->cells.size() * sizeof(Cell) + MASTER_HASH_LEN + 1;
    uint8_t* out_buffer = (uint8_t*)malloc(sizeof(size_t) + vault_size);
    size_t cells_size = vault->cells.size();
    memcpy(out_buffer, &cells_size, sizeof(size_t));
    memcpy(out_buffer + sizeof(size_t), vault->master_hash, MASTER_HASH_LEN + 1);
    for (unsigned i = 0; i < vault->cells.size(); ++i){
        memcpy(out_buffer + sizeof(size_t) + MASTER_HASH_LEN + 1 + i * sizeof(Cell), &(vault->cells.at(i)), sizeof(Cell));
    }
    
    size_t sealed_size = sizeof(sgx_sealed_data_t) + vault_size + sizeof(size_t);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_vault(out_buffer, vault_size + sizeof(size_t), (sgx_sealed_data_t*) sealed_data, sealed_size);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        free(out_buffer);
        return ERR_CANNOT_SEAL_VAULT;
    }

    // save sealed vault
    sgx_status_t save_to_file_status;
    int save_to_file_ret;

    save_to_file_status = ocall_save_to_file(&save_to_file_ret, sealed_data, sealed_size);
    free(sealed_data);
    free(out_buffer);
    if (save_to_file_ret != RET_SUCCESS || save_to_file_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_TO_FILE;
    }
    
    // save vault size
    save_to_file_status = ocall_save_size_to_file(&save_to_file_ret, (uint8_t *) &vault_size, sizeof(sgx_sealed_data_t) + sizeof(size_t));
    if (save_to_file_ret != RET_SUCCESS || save_to_file_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_TO_FILE;
    }
    
    return RET_SUCCESS;
}

// read from file and unseal
int ecall_get_vault(Vault* vault) {
    sgx_status_t load_from_file;
    int load_from_file_ret;
    
    // load vault size
    size_t vault_size = 0;
    size_t sealed_vault_size_size = sizeof(sgx_sealed_data_t) + sizeof(size_t);
    
    uint8_t sealed_vault_size[sealed_vault_size_size];
    load_from_file = ocall_load_size_from_file(&load_from_file_ret, sealed_vault_size, sealed_vault_size_size);
    if (load_from_file_ret != RET_SUCCESS || load_from_file != SGX_SUCCESS) {
        return ERR_CANNOT_LOAD_FROM_FILE;
    }
    
    // unseal vault size
    sgx_status_t size_sealing_status = unseal_vault_size((sgx_sealed_data_t*) sealed_vault_size, vault_size);
    if (size_sealing_status != SGX_SUCCESS) {
        free(vault);
        return ERR_CANNOT_UNSEAL_VAULT;
    }
    
    // load vault
    size_t sealed_size  = sizeof(sgx_sealed_data_t) + vault_size;
    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);
    load_from_file = ocall_load_from_file(&load_from_file_ret, sealed_data, sealed_size);
    if (load_from_file_ret != RET_SUCCESS || load_from_file != SGX_SUCCESS) {
        return ERR_CANNOT_LOAD_FROM_FILE;
    }
    uint8_t* plaintext_data = (uint8_t*)malloc(vault_size);

    // unseal loaded vault
    sgx_status_t sealing_status = unseal_vault((sgx_sealed_data_t*) sealed_data, plaintext_data, vault_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(vault);
        free(plaintext_data);
        return ERR_CANNOT_UNSEAL_VAULT;
    }
    size_t cells_count = 0;
    memcpy(&cells_count, plaintext_data, sizeof(size_t));
    memcpy(vault->master_hash, plaintext_data + sizeof(size_t), MASTER_HASH_LEN + 1);
    vault->cells.resize(cells_count);
    for (size_t i = 0; i < cells_count; ++i) {
        memcpy(&(vault->cells.at(i)), plaintext_data + sizeof(size_t) + MASTER_HASH_LEN + 1 + i * sizeof(Cell), sizeof(Cell));
    }

    return RET_SUCCESS;
}
