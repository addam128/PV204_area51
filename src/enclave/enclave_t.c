#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_create_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_wallet_t* ms = SGX_CAST(ms_ecall_create_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_create_wallet((const char*)_in_master_password);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_list_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_list_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_list_wallet_t* ms = SGX_CAST(ms_ecall_list_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_list_wallet((const char*)_in_master_password);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_old_password = ms->ms_old_password;
	size_t _len_old_password = ms->ms_old_password_len ;
	char* _in_old_password = NULL;
	const char* _tmp_new_password = ms->ms_new_password;
	size_t _len_new_password = ms->ms_new_password_len ;
	char* _in_new_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_old_password, _len_old_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_password != NULL && _len_old_password != 0) {
		_in_old_password = (char*)malloc(_len_old_password);
		if (_in_old_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_password, _len_old_password, _tmp_old_password, _len_old_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_old_password[_len_old_password - 1] = '\0';
		if (_len_old_password != strlen(_in_old_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_new_password != NULL && _len_new_password != 0) {
		_in_new_password = (char*)malloc(_len_new_password);
		if (_in_new_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_password, _len_new_password, _tmp_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_new_password[_len_new_password - 1] = '\0';
		if (_len_new_password != strlen(_in_new_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_change_master_password((const char*)_in_old_password, (const char*)_in_new_password);

err:
	if (_in_old_password) free(_in_old_password);
	if (_in_new_password) free(_in_new_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_entry(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_entry_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_entry_t* ms = SGX_CAST(ms_ecall_add_entry_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;
	const char* _tmp_service = ms->ms_service;
	size_t _len_service = ms->ms_service_len ;
	char* _in_service = NULL;
	const char* _tmp_username = ms->ms_username;
	size_t _len_username = ms->ms_username_len ;
	char* _in_username = NULL;
	const char* _tmp_password = ms->ms_password;
	size_t _len_password = ms->ms_password_len ;
	char* _in_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);
	CHECK_UNIQUE_POINTER(_tmp_username, _len_username);
	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_username != NULL && _len_username != 0) {
		_in_username = (char*)malloc(_len_username);
		if (_in_username == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_username, _len_username, _tmp_username, _len_username)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_username[_len_username - 1] = '\0';
		if (_len_username != strlen(_in_username) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_password, _len_password, _tmp_password, _len_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_add_entry((const char*)_in_master_password, (const char*)_in_service, (const char*)_in_username, (const char*)_in_password);

err:
	if (_in_master_password) free(_in_master_password);
	if (_in_service) free(_in_service);
	if (_in_username) free(_in_username);
	if (_in_password) free(_in_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_list_entry(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_list_entry_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_list_entry_t* ms = SGX_CAST(ms_ecall_list_entry_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;
	const char* _tmp_service = ms->ms_service;
	size_t _len_service = ms->ms_service_len ;
	char* _in_service = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_service, _len_service);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_service != NULL && _len_service != 0) {
		_in_service = (char*)malloc(_len_service);
		if (_in_service == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_service, _len_service, _tmp_service, _len_service)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_service[_len_service - 1] = '\0';
		if (_len_service != strlen(_in_service) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_list_entry((const char*)_in_master_password, (const char*)_in_service);

err:
	if (_in_master_password) free(_in_master_password);
	if (_in_service) free(_in_service);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_wallet_t* ms = SGX_CAST(ms_ecall_get_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_serialized_wallet = ms->ms_serialized_wallet;
	size_t _len_serialized_wallet = ms->ms_serialized_wallet_len ;
	char* _in_serialized_wallet = NULL;

	CHECK_UNIQUE_POINTER(_tmp_serialized_wallet, _len_serialized_wallet);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_serialized_wallet != NULL && _len_serialized_wallet != 0) {
		_in_serialized_wallet = (char*)malloc(_len_serialized_wallet);
		if (_in_serialized_wallet == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_serialized_wallet, _len_serialized_wallet, _tmp_serialized_wallet, _len_serialized_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_serialized_wallet[_len_serialized_wallet - 1] = '\0';
		if (_len_serialized_wallet != strlen(_in_serialized_wallet) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_get_wallet(_in_serialized_wallet);
	if (_in_serialized_wallet)
	{
		_in_serialized_wallet[_len_serialized_wallet - 1] = '\0';
		_len_serialized_wallet = strlen(_in_serialized_wallet) + 1;
		if (memcpy_s((void*)_tmp_serialized_wallet, _len_serialized_wallet, _in_serialized_wallet, _len_serialized_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_serialized_wallet) free(_in_serialized_wallet);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_store_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_store_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_store_wallet_t* ms = SGX_CAST(ms_ecall_store_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_serialized_wallet = ms->ms_serialized_wallet;
	size_t _len_serialized_wallet = ms->ms_serialized_wallet_len ;
	char* _in_serialized_wallet = NULL;

	CHECK_UNIQUE_POINTER(_tmp_serialized_wallet, _len_serialized_wallet);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_serialized_wallet != NULL && _len_serialized_wallet != 0) {
		_in_serialized_wallet = (char*)malloc(_len_serialized_wallet);
		if (_in_serialized_wallet == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_serialized_wallet, _len_serialized_wallet, _tmp_serialized_wallet, _len_serialized_wallet)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_serialized_wallet[_len_serialized_wallet - 1] = '\0';
		if (_len_serialized_wallet != strlen(_in_serialized_wallet) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_store_wallet((const char*)_in_serialized_wallet, ms->ms_serialized_wallet_size);

err:
	if (_in_serialized_wallet) free(_in_serialized_wallet);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_ecall_create_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_list_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_entry, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_list_entry, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_wallet, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_store_wallet, 1, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[5][7];
} g_dyn_entry_table = {
	5,
	{
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_save_to_file(int* retval, const uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = sealed_size;

	ms_ocall_save_to_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_save_to_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_save_to_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_save_to_file_t));
	ocalloc_size -= sizeof(ms_ocall_save_to_file_t);

	if (sealed_data != NULL) {
		ms->ms_sealed_data = (const uint8_t*)__tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, sealed_data, _len_sealed_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_load_from_file(int* retval, uint8_t* sealed_data, size_t sealed_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sealed_data = sealed_size;

	ms_ocall_load_from_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_from_file_t);
	void *__tmp = NULL;

	void *__tmp_sealed_data = NULL;

	CHECK_ENCLAVE_POINTER(sealed_data, _len_sealed_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sealed_data != NULL) ? _len_sealed_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_from_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_from_file_t));
	ocalloc_size -= sizeof(ms_ocall_load_from_file_t);

	if (sealed_data != NULL) {
		ms->ms_sealed_data = (uint8_t*)__tmp;
		__tmp_sealed_data = __tmp;
		if (_len_sealed_data % sizeof(*sealed_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_sealed_data, 0, _len_sealed_data);
		__tmp = (void *)((size_t)__tmp + _len_sealed_data);
		ocalloc_size -= _len_sealed_data;
	} else {
		ms->ms_sealed_data = NULL;
	}
	
	ms->ms_sealed_size = sealed_size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sealed_data) {
			if (memcpy_s((void*)sealed_data, _len_sealed_data, __tmp_sealed_data, _len_sealed_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_credentials(int* retval, const char* service, const char* username, const char* password)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_service = service ? strlen(service) + 1 : 0;
	size_t _len_username = username ? strlen(username) + 1 : 0;
	size_t _len_password = password ? strlen(password) + 1 : 0;

	ms_ocall_print_credentials_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_credentials_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(service, _len_service);
	CHECK_ENCLAVE_POINTER(username, _len_username);
	CHECK_ENCLAVE_POINTER(password, _len_password);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (service != NULL) ? _len_service : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (username != NULL) ? _len_username : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (password != NULL) ? _len_password : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_credentials_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_credentials_t));
	ocalloc_size -= sizeof(ms_ocall_print_credentials_t);

	if (service != NULL) {
		ms->ms_service = (const char*)__tmp;
		if (_len_service % sizeof(*service) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, service, _len_service)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_service);
		ocalloc_size -= _len_service;
	} else {
		ms->ms_service = NULL;
	}
	
	if (username != NULL) {
		ms->ms_username = (const char*)__tmp;
		if (_len_username % sizeof(*username) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, username, _len_username)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_username);
		ocalloc_size -= _len_username;
	} else {
		ms->ms_username = NULL;
	}
	
	if (password != NULL) {
		ms->ms_password = (const char*)__tmp;
		if (_len_password % sizeof(*password) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, password, _len_password)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_password);
		ocalloc_size -= _len_password;
	} else {
		ms->ms_password = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_get_wallet_size(int* retval, size_t* wallet_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wallet_size = sizeof(size_t);

	ms_ocall_get_wallet_size_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_get_wallet_size_t);
	void *__tmp = NULL;

	void *__tmp_wallet_size = NULL;

	CHECK_ENCLAVE_POINTER(wallet_size, _len_wallet_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (wallet_size != NULL) ? _len_wallet_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_get_wallet_size_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_get_wallet_size_t));
	ocalloc_size -= sizeof(ms_ocall_get_wallet_size_t);

	if (wallet_size != NULL) {
		ms->ms_wallet_size = (size_t*)__tmp;
		__tmp_wallet_size = __tmp;
		if (_len_wallet_size % sizeof(*wallet_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_wallet_size, 0, _len_wallet_size);
		__tmp = (void *)((size_t)__tmp + _len_wallet_size);
		ocalloc_size -= _len_wallet_size;
	} else {
		ms->ms_wallet_size = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (wallet_size) {
			if (memcpy_s((void*)wallet_size, _len_wallet_size, __tmp_wallet_size, _len_wallet_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_wallet_exists(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_wallet_exists_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_wallet_exists_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_wallet_exists_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_wallet_exists_t));
	ocalloc_size -= sizeof(ms_ocall_wallet_exists_t);

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

