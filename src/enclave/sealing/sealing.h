#ifndef SEALING_H_
#define SEALING_H_

#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "../../simplevault/simplevault.hpp"

sgx_status_t seal_vault(const vault_t* plaintext, sgx_sealed_data_t* sealed_data, size_t sealed_size);

sgx_status_t unseal_vault(const sgx_sealed_data_t* sealed_data, vault_t* plaintext, uint32_t plaintext_size);


#endif // SEALING_H_
