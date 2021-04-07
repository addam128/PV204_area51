#include <sodium.h>
#include "../cli/password.hpp"
#include "../cli/error.hpp"
#include "../cli/terminal.hpp"

#include "sgx_urts.h"

const char* ENCLAVE_FILE = "src/enclave.signed.so";

int main() {
    if (sodium_init() < 0) {
        std::cerr << "panic! Could not init crypto library, exiting!" << std::endl;
        exit(1);
    }

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int  updated;
    sgx_status_t enclave_status;


    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if(enclave_status != SGX_SUCCESS) {
        std::cerr <<  "Fail to initialize enclave."<< std::endl;
        return -1;
    }

    Term::spawn(eid);

    enclave_status = sgx_destroy_enclave(eid);
    if(enclave_status != SGX_SUCCESS) {
        std::cerr << "Fail to destroy enclave." << std::endl;
        return -1;
    }

    return 0;
}