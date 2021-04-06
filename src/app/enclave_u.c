#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_create_wallet_t;

typedef struct ms_ecall_list_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_list_wallet_t;

typedef struct ms_ecall_change_master_password_t {
	int ms_retval;
	const char* ms_old_password;
	size_t ms_old_password_len;
	const char* ms_new_password;
	size_t ms_new_password_len;
} ms_ecall_change_master_password_t;

typedef struct ms_ecall_add_entry_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	const char* ms_service;
	size_t ms_service_len;
	const char* ms_username;
	size_t ms_username_len;
	const char* ms_password;
	size_t ms_password_len;
} ms_ecall_add_entry_t;

typedef struct ms_ecall_list_entry_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	const char* ms_service;
	size_t ms_service_len;
} ms_ecall_list_entry_t;

typedef struct ms_ecall_get_wallet_t {
	int ms_retval;
	char* ms_serialized_wallet;
	size_t ms_serialized_wallet_len;
} ms_ecall_get_wallet_t;

typedef struct ms_ecall_store_wallet_t {
	int ms_retval;
	const char* ms_serialized_wallet;
	size_t ms_serialized_wallet_len;
	size_t ms_serialized_wallet_size;
} ms_ecall_store_wallet_t;

typedef struct ms_ocall_save_to_file_t {
	int ms_retval;
	const uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_save_to_file_t;

typedef struct ms_ocall_load_from_file_t {
	int ms_retval;
	uint8_t* ms_sealed_data;
	size_t ms_sealed_size;
} ms_ocall_load_from_file_t;

typedef struct ms_ocall_print_credentials_t {
	int ms_retval;
	const char* ms_service;
	const char* ms_username;
	const char* ms_password;
} ms_ocall_print_credentials_t;

typedef struct ms_ocall_get_wallet_size_t {
	int ms_retval;
	size_t* ms_wallet_size;
} ms_ocall_get_wallet_size_t;

typedef struct ms_ocall_wallet_exists_t {
	int ms_retval;
} ms_ocall_wallet_exists_t;

static sgx_status_t SGX_CDECL enclave_ocall_save_to_file(void* pms)
{
	ms_ocall_save_to_file_t* ms = SGX_CAST(ms_ocall_save_to_file_t*, pms);
	ms->ms_retval = ocall_save_to_file(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_load_from_file(void* pms)
{
	ms_ocall_load_from_file_t* ms = SGX_CAST(ms_ocall_load_from_file_t*, pms);
	ms->ms_retval = ocall_load_from_file(ms->ms_sealed_data, ms->ms_sealed_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_credentials(void* pms)
{
	ms_ocall_print_credentials_t* ms = SGX_CAST(ms_ocall_print_credentials_t*, pms);
	ms->ms_retval = ocall_print_credentials(ms->ms_service, ms->ms_username, ms->ms_password);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_get_wallet_size(void* pms)
{
	ms_ocall_get_wallet_size_t* ms = SGX_CAST(ms_ocall_get_wallet_size_t*, pms);
	ms->ms_retval = ocall_get_wallet_size(ms->ms_wallet_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_wallet_exists(void* pms)
{
	ms_ocall_wallet_exists_t* ms = SGX_CAST(ms_ocall_wallet_exists_t*, pms);
	ms->ms_retval = ocall_wallet_exists();

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_enclave = {
	5,
	{
		(void*)enclave_ocall_save_to_file,
		(void*)enclave_ocall_load_from_file,
		(void*)enclave_ocall_print_credentials,
		(void*)enclave_ocall_get_wallet_size,
		(void*)enclave_ocall_wallet_exists,
	}
};
sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_create_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_list_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password)
{
	sgx_status_t status;
	ms_ecall_list_wallet_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password)
{
	sgx_status_t status;
	ms_ecall_change_master_password_t ms;
	ms.ms_old_password = old_password;
	ms.ms_old_password_len = old_password ? strlen(old_password) + 1 : 0;
	ms.ms_new_password = new_password;
	ms.ms_new_password_len = new_password ? strlen(new_password) + 1 : 0;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_add_entry(sgx_enclave_id_t eid, int* retval, const char* master_password, const char* service, const char* username, const char* password)
{
	sgx_status_t status;
	ms_ecall_add_entry_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	ms.ms_username = username;
	ms.ms_username_len = username ? strlen(username) + 1 : 0;
	ms.ms_password = password;
	ms.ms_password_len = password ? strlen(password) + 1 : 0;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_list_entry(sgx_enclave_id_t eid, int* retval, const char* master_password, const char* service)
{
	sgx_status_t status;
	ms_ecall_list_entry_t ms;
	ms.ms_master_password = master_password;
	ms.ms_master_password_len = master_password ? strlen(master_password) + 1 : 0;
	ms.ms_service = service;
	ms.ms_service_len = service ? strlen(service) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_wallet(sgx_enclave_id_t eid, int* retval, char* serialized_wallet)
{
	sgx_status_t status;
	ms_ecall_get_wallet_t ms;
	ms.ms_serialized_wallet = serialized_wallet;
	ms.ms_serialized_wallet_len = serialized_wallet ? strlen(serialized_wallet) + 1 : 0;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_store_wallet(sgx_enclave_id_t eid, int* retval, const char* serialized_wallet, size_t serialized_wallet_size)
{
	sgx_status_t status;
	ms_ecall_store_wallet_t ms;
	ms.ms_serialized_wallet = serialized_wallet;
	ms.ms_serialized_wallet_len = serialized_wallet ? strlen(serialized_wallet) + 1 : 0;
	ms.ms_serialized_wallet_size = serialized_wallet_size;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

