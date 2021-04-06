#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "../simplevault/simplevault.hpp"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_create_wallet(const char* master_password);
int ecall_list_wallet(const char* master_password);
int ecall_change_master_password(const char* old_password, const char* new_password);
int ecall_add_entry(const char* master_password, const char* service, const char* username, const char* password);
int ecall_list_entry(const char* master_password, const char* service);
int ecall_get_wallet(char* serialized_wallet);
int ecall_store_wallet(const char* serialized_wallet, size_t serialized_wallet_size);

sgx_status_t SGX_CDECL ocall_save_to_file(int* retval, const uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_load_from_file(int* retval, uint8_t* sealed_data, size_t sealed_size);
sgx_status_t SGX_CDECL ocall_print_credentials(int* retval, const char* service, const char* username, const char* password);
sgx_status_t SGX_CDECL ocall_get_wallet_size(int* retval, size_t* wallet_size);
sgx_status_t SGX_CDECL ocall_wallet_exists(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
