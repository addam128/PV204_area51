#pragma once

#include "password.hpp"
#include "prompt.hpp"
#include "enclave_u.h"
#include "sgx_urts.h"

namespace commands {

    void list(sgx_enclave_id_t eid);
    void search(sgx_enclave_id_t eid);
    void change_master(sgx_enclave_id_t eid);
    void new_entry(sgx_enclave_id_t eid);
    void remove_entry(sgx_enclave_id_t eid);
    void create_facility(sgx_enclave_id_t eid);
    void print_help();
}