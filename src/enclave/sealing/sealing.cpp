#include "../enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "../../simplevault/simplevault.hpp"
#include "sealing.h"

sgx_status_t seal_vault(const uint8_t* vault, size_t plaintext_size, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    return sgx_seal_data(0, NULL, plaintext_size, vault, sealed_size, sealed_data);
}

sgx_status_t unseal_vault(const sgx_sealed_data_t* sealed_data, uint8_t* plaintext, uint32_t plaintext_size) {
    return sgx_unseal_data(sealed_data, NULL, NULL, plaintext, &plaintext_size);
}

sgx_status_t seal_vault_size(const uint8_t* vault_size, sgx_sealed_data_t* sealed_vault_size, size_t sealed_size) {
    return sgx_seal_data(0, NULL, sizeof(size_t), vault_size, sealed_size, sealed_vault_size);
}

sgx_status_t unseal_vault_size(const sgx_sealed_data_t* sealed_vault_size, size_t vault_size) {
    uint32_t vault_size_size = (uint32_t) sizeof(size_t);
    return sgx_unseal_data(sealed_vault_size, NULL, NULL, (uint8_t *) &vault_size, &vault_size_size);
}

