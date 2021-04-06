#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "../simplevault/simplevault.hpp"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_SAVE_TO_FILE_DEFINED__
#define OCALL_SAVE_TO_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_to_file, (const uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_LOAD_FROM_FILE_DEFINED__
#define OCALL_LOAD_FROM_FILE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_from_file, (uint8_t* sealed_data, size_t sealed_size));
#endif
#ifndef OCALL_PRINT_CREDENTIALS_DEFINED__
#define OCALL_PRINT_CREDENTIALS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_credentials, (const char* service, const char* username, const char* password));
#endif
#ifndef OCALL_GET_WALLET_SIZE_DEFINED__
#define OCALL_GET_WALLET_SIZE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_get_wallet_size, (size_t* wallet_size));
#endif
#ifndef OCALL_WALLET_EXISTS_DEFINED__
#define OCALL_WALLET_EXISTS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_wallet_exists, (void));
#endif

sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_list_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password);
sgx_status_t ecall_add_entry(sgx_enclave_id_t eid, int* retval, const char* master_password, const char* service, const char* username, const char* password);
sgx_status_t ecall_list_entry(sgx_enclave_id_t eid, int* retval, const char* master_password, const char* service);
sgx_status_t ecall_get_wallet(sgx_enclave_id_t eid, int* retval, char* serialized_wallet);
sgx_status_t ecall_store_wallet(sgx_enclave_id_t eid, int* retval, const char* serialized_wallet, size_t serialized_wallet_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
