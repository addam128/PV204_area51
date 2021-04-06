#include "pwmanager.pb.h"
#include <string.h>

#include "sgx_tseal.h"
#include "sealing/sealing.h"

int ecall_create_wallet(const char* master_password) {
    // check if wallet already exists
    sgx_status_t is_wallet_status;
    int is_wallet_ret;
    is_wallet_status = ocall_is_wallet(&is_wallet_ret);
    if (is_wallet_ret != 0) {
        return -1 // TODO: Add proper error codes
    }

    // create new wallet
    Wallet wallet;
    wallet.set_master_password(master_password);
    wallet.set_number_of_entries(0);

    // serialize and call store_wallet
    std::string serialized_protobuf;

    wallet.SerializeToString(&serialized_protobuf); //TODO: error handling
    const char* serialized_char = serialized_protobuf.c_str();
    size_t sealing_size = sizeof(sgx_sealed_data_t) + serialized_protobuf.size() + 1;

    sgx_status_t store_status;
    int store_ret;
    store_status = ecall_store_wallet(&store_ret); //TODO: error handling

    return 0;
}

int ecall_list_wallet(const char* master_password) {
    // load serialized wallet
    sgx_status_t get_wallet_status;
    int get_wallet_ret;
    const char*  serialized_wallet;
    get_wallet_status = ecall_get_wallet(&get_wallet_ret, serialized_wallet); //TODO: error handling

    // deserialize wallet
    std::string serialized_wallet_string(serialized_wallet);
    Wallet wallet;
    wallet.ParseFromString(serialized_wallet_string);

    // check master password
    if (wallet.master_password().compare(std::string pass(master_password)) != 0) {
        free(serialized_wallet);
        return -1;
    }

    //TODO: iterate through entries and call ocall_print_credentials on each

    free(serialized_wallet);
    return 0;
}

int ecall_change_master_password(const char* old_password, const char* new_password) {
    // load serialized wallet
    sgx_status_t get_wallet_status;
    int get_wallet_ret;
    const char*  serialized_wallet;
    get_wallet_status = ecall_get_wallet(&get_wallet_ret, serialized_wallet); //TODO: error handling

    // deserialize wallet
    std::string serialized_wallet_string(serialized_wallet);
    Wallet wallet;
    wallet.ParseFromString(serialized_wallet_string);

    // check master password
    if (wallet.master_password().compare(std::string pass(old_password)) != 0) {
        free(serialized_wallet);
        return -1;
    }

    wallet.set_master_password(new_password);

    // serialize and call store_wallet
    std::string serialized_protobuf;

    wallet.SerializeToString(&serialized_protobuf); //TODO: error handling
    const char* serialized_char = serialized_protobuf.c_str();
    size_t sealing_size = sizeof(sgx_sealed_data_t) + serialized_protobuf.size() + 1;

    sgx_status_t store_status;
    int store_ret;
    store_status = ecall_store_wallet(&store_ret); //TODO: error handling

    return 0;
}

int ecall_add_entry(const char* master_password, const char* service, const char* username, const char* password) {
    // load serialized wallet
    sgx_status_t get_wallet_status;
    int get_wallet_ret;
    const char*  serialized_wallet;
    get_wallet_status = ecall_get_wallet(&get_wallet_ret, serialized_wallet); //TODO: error handling

    // deserialize wallet
    std::string serialized_wallet_string(serialized_wallet);
    Wallet wallet;
    wallet.ParseFromString(serialized_wallet_string);

    // check master password
    if (wallet.master_password().compare(std::string pass(old_password)) != 0) {
        free(serialized_wallet);
        return -1;
    }

    //TODO: Add new entry

    // serialize and call store_wallet
    std::string serialized_protobuf;

    wallet.SerializeToString(&serialized_protobuf); //TODO: error handling
    const char* serialized_char = serialized_protobuf.c_str();
    size_t sealing_size = sizeof(sgx_sealed_data_t) + serialized_protobuf.size() + 1;

    sgx_status_t store_status;
    int store_ret;
    store_status = ecall_store_wallet(&store_ret); //TODO: error handling

    return 0;
}

int ecall_list_entry(const char* master_password, const char* service) {
    // load serialized wallet
    sgx_status_t get_wallet_status;
    int get_wallet_ret;
    const char*  serialized_wallet;
    get_wallet_status = ecall_get_wallet(&get_wallet_ret, serialized_wallet); //TODO: error handling

    // deserialize wallet
    std::string serialized_wallet_string(serialized_wallet);
    Wallet wallet;
    wallet.ParseFromString(serialized_wallet_string);

    // check master password
    if (wallet.master_password().compare(std::string pass(old_password)) != 0) {
        free(serialized_wallet);
        return -1;
    }

    // TODO: list entry (call ocall_print_credentials)

    free(serialized_wallet);
    return 0;
}

// seal and save wallet to file
//TODO: see page 94 of the following link for length calculation https://download.01.org/intel-sgx/linux-1.8/docs/Intel_SGX_SDK_Developer_Reference_Linux_1.8_Open_Source.pdf
int ecall_store_wallet(const char* serialized_wallet, size_t serialized_wallet_size) {
    // seal wallet
    sgx_status_t sealing_status;

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(); // TODO: implement sealing
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // save sealed wallet
    sgx_status_t save_to_file_status;
    int save_to_file_ret;

    save_to_file_status = ocall_save_to_file(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (save_to_file_ret != 0 || save_to_file_ret != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

// read from file and unseal
//TODO: see page 94 of the following link for length calculation https://download.01.org/intel-sgx/linux-1.8/docs/Intel_SGX_SDK_Developer_Reference_Linux_1.8_Open_Source.pdf
int ecall_get_wallet(char* serialized_wallet) {
    // get maximal possible wallet size
    sgx_status_t wallet_size_status;
    int wallet_size_ret;
    size_t wallet_size;
    wallet_size_status = ocall_get_wallet_size(&wallet_size_ret, &wallet_size);
    size_t sealed_size = sizeof(sgx_sealed_data_t) + wallet_size();

    // load wallet
    char* sealed_wallet = (char*) malloc(sealed_size);
    sgx_status_t load_wallet_status;
    int load_wallet_ret;
    load_wallet_status = ocall_load_from_file(&load_wallet_ret, sealed_wallet, sealed_size);

    // unseal loaded wallet
    size_t serialized_wallet_size = 0; // TODO: Add calculation
    sgx_status_t sealing_status = unseal_wallet((sgx_sealed_data_t*) sealed_wallet, serialized_wallet, serialized_wallet_size);
    free(sealed_wallet);
    if (sealing_status != SGX_SUCCESS) {
        free(serialized_wallet);
        return -1;
    }

    return 0;
}



