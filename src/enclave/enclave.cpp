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
    vault->cell_count = 0;
    memcpy(vault->master_hash, master_hash, MASTER_HASH_LEN);

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault, sizeof(Vault));
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
    size_t vault_size = sizeof(Vault);
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault, vault_size); //TODO: error handling
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }


    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }
    int retval = 0;
    for (int i = 0; i < vault->cell_count; ++i) {
        ocall_print_credentials(&retval, vault->cells[i]._service, vault->cells[i]._username, NULL);   // TODO error check
    }

    free(vault);
    return RET_SUCCESS;
}

int ecall_change_master_password(const char* old_master_hash, const char* new_master_hash) {
    // load serialized vault
    sgx_status_t get_vault_status;
    Vault* vault = (Vault*)calloc(1, sizeof(Vault));
    size_t vault_size = sizeof(Vault);
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault, vault_size);
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
    store_ret = ecall_store_vault( vault, sizeof(Vault));
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
    size_t vault_size = sizeof(Vault);
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault, vault_size);
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }


    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }
    if (vault->cell_count >= VAULT_MAX) {
        free(vault);
        return ERR_VAULT_FULL;
    }
    strncpy(vault->cells[vault->cell_count]._service, service, MAX_SERVICE_N_USER_LEN);
    strncpy(vault->cells[vault->cell_count]._username, username, MAX_SERVICE_N_USER_LEN);
    strncpy(vault->cells[vault->cell_count]._password, password, MAX_PWD_LEN);
    vault->cell_count += 1;  

    // seal and store
    sgx_status_t store_status;
    int store_ret;
    store_ret = ecall_store_vault(vault, sizeof(Vault)); //TODO: error handling
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
    size_t vault_size = sizeof(Vault);
    int get_vault_ret;
    get_vault_ret = ecall_get_vault(vault, vault_size); //TODO: error handling
    if (get_vault_ret != RET_SUCCESS) {
        return get_vault_ret;
    }

    // check master password
    if (memcmp(vault->master_hash, master_hash, MASTER_HASH_LEN) != 0) {
        free(vault);
        return ERR_INVALID_MASTER_PASSWORD;
    }

    int retval = 0;
    for (int i = 0; i < vault->cell_count; ++i) {
        if (strncmp(service, vault->cells[i]._service, MAX_SERVICE_N_USER_LEN) == 0) {
            ocall_print_credentials(&retval, service, vault->cells[i]._username, NULL);   // TODO error check
        }
    }

    free(vault);
    return RET_SUCCESS;
}

// seal and save vault to file
int ecall_store_vault(Vault* vault, size_t vault_size) {
    // seal vault
    sgx_status_t sealing_status;

    size_t sealed_size = sizeof(sgx_sealed_data_t) + vault_size;
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_vault(vault, (sgx_sealed_data_t*) sealed_data, sealed_size);
    //free(vault);
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_CANNOT_SEAL_VAULT;
    }

    // save sealed vault
    sgx_status_t save_to_file_status;
    int save_to_file_ret;

    save_to_file_status = ocall_save_to_file(&save_to_file_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (save_to_file_ret != RET_SUCCESS || save_to_file_status != SGX_SUCCESS) {
        return ERR_CANNOT_SAVE_TO_FILE;
    }

    return RET_SUCCESS;
}

// read from file and unseal
int ecall_get_vault(Vault* vault, size_t vault_size) {
    sgx_status_t load_from_file;
    int load_from_file_ret;
    // load vault
    size_t sealed_size  = sizeof(sgx_sealed_data_t) + vault_size;
    uint8_t* sealed_data = (uint8_t*) malloc(sealed_size);
    load_from_file = ocall_load_from_file(&load_from_file_ret, sealed_data, sealed_size);
    if (load_from_file_ret != RET_SUCCESS || load_from_file != SGX_SUCCESS) {
        return ERR_CANNOT_LOAD_FROM_FILE;
    }

    // unseal loaded vault
    sgx_status_t sealing_status = unseal_vault((sgx_sealed_data_t*) sealed_data, vault, vault_size);
    free(sealed_data);
    if (sealing_status != SGX_SUCCESS) {
        free(vault);
        return ERR_CANNOT_UNSEAL_VAULT;
    }

    return RET_SUCCESS;
}