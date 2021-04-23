#pragma once

#include "password.hpp"
#include "utils.hpp"
#include "prompt.hpp"
#include "enclave_u.h"
#include "sgx_urts.h"
#include "error.hpp"
#include <fstream>

namespace commands {

    extern std::string chosen_vault;

    void list(sgx_enclave_id_t eid);
    void search(sgx_enclave_id_t eid);
    void change_master(sgx_enclave_id_t eid);
    void new_entry(sgx_enclave_id_t eid);
    void remove_entry(sgx_enclave_id_t eid);
    void change_entry(sgx_enclave_id_t eid);
    void create_facility(sgx_enclave_id_t eid);
    void choose_vault();
    void set_vault(const std::string&);
    void print_help();
}