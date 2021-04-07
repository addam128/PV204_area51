#include <stdlib.h>
#include "enclave_u.h"
#include "constants.hpp"
#include <fstream>
#include <iostream>


typedef unsigned char uint8_t;


int ocall_save_to_file(const uint8_t* sealed_data, size_t sealed_size) {
    std::ofstream file(VAULT_FILE, std::ios::out | std::ios::binary);
    if (file.fail()) {
        return 1;
    }
    file.write((const char*)sealed_data, sealed_size);
    file.flush();
    file.close();
    return 0;
}


int ocall_load_from_file(uint8_t* sealed_data, size_t sealed_size) {
    std::ifstream file(VAULT_FILE, std::ios::in | std::ios::binary);
    if (file.fail()) {
        std::cerr << "Vault file missing." << std::endl; 
        return 1;
    }
    file.read((char*)sealed_data, sealed_size);
    file.close();
    return 0;
}

int ocall_print_credentials(const char* service, const char* username, const char* password) {
    std::cout<< service << "     " << username <<   "     " << ((password) ? password : "") << std::endl;
    std::cout << std::endl;
    
    return 0;
}

int ocall_vault_exists() {
    std::ifstream file(VAULT_FILE, std::ios::in | std::ios::binary);
    if (file.fail()) {
        return 0;
    }
    std::cout << "Vault already exists." << std::endl;
    file.close();
    return 1;
}

int ocall_get_vault_size(size_t* wallet_size) {
    return 0;
}


