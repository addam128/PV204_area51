#include "enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "../../simplevault/simplevault.hpp"
#include "sealing.h"

sgx_status_t seal_vault(const Vault* vault, sgx_sealed_data_t* sealed_data, size_t sealed_size) {
    return sgx_seal_data(0, NULL, sizeof(vault), (uint8_t*)vault, sealed_size, sealed_data);
}

sgx_status_t unseal_vault(const sgx_sealed_data_t* sealed_data, Vault* plaintext, uint32_t plaintext_size) {
    return sgx_unseal_data(sealed_data, NULL, NULL, (uint8_t*)plaintext, &plaintext_size);
}

