#include "pwmanager.pb.h"
#include "string.h"

#include "sgx_tseal.h"
#include "sealing/sealing.h"

public int ecall_create_wallet(const char* master_password) {

    // check if wallet already exists
    sgx_status_e ocall_status;
    int ocall_ret;
    ocall_status = ocall_is_wallet(&ocall_ret);
    if (ocall_ret != 0) {
        return -1 // TODO: Add proper error codes
    }

    // create new wallet
    Wallet wallet;
    wallet.set_master_password(master_password);
    wallet.set_number_of_entries(0);

    // seal wallet
    sgx_status_e sealing_status;
    std::string serialized_protobuf;

    wallet.SerializeToString(&serialized_protobuf); //TODO: error handling
    const char* serialized_proto = serialized_protobuf.c_str();
    size_t sealing_size = sizeof(sgx_sealed_data_t) + serialized_protobuf.size() + 1;

    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);
    sealing_status = seal_wallet(); // TODO: implement sealing
    if (sealing_status != SGX_SUCCESS) {
        free(sealed_data);
        return ERR_FAIL_SEAL;
    }

    // save sealed wallet
    ocall_status = ocall_save_wallet(&ocall_ret, sealed_data, sealed_size);
    free(sealed_data);
    if (ocall_ret != 0 || ocall_status != SGX_SUCCESS) {
        return -1;
    }

    return 0;
}

public int ecall_list_wallet(const char* master_password) {

}

public int ecall_change_master_password(const char* old_password, const char* new_password) {

}

public int ecall_add_entry(const char* master_password, const char* service, const char* username, const char* password) {

}

public int ecall_list_entry(const char* master_password, const char* service) {

}

};


