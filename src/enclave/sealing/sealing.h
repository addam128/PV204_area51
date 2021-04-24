#ifndef SEALING_H_
#define SEALING_H_

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "../../simplevault/simplevault.hpp"

sgx_status_t seal_vault(const uint8_t* vault, size_t plaintext_size, sgx_sealed_data_t* sealed_data, size_t sealed_size);

sgx_status_t unseal_vault(const sgx_sealed_data_t* sealed_data, uint8_t* plaintext, uint32_t plaintext_size);

sgx_status_t seal_vault_size(const uint8_t* vault_size, sgx_sealed_data_t* sealed_vault_size, size_t sealed_size);

sgx_status_t unseal_vault_size(const sgx_sealed_data_t* sealed_vault_size, size_t vault_size);

#endif // SEALING_H_
