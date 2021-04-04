#include <cstring>
#include <fstream>

int ocall_save_to_file(const uint8_t* sealed_data, size_t sealed_size) {
    return 0;
}

int ocall_load_from_file(uint8_t* sealed_data, size_t sealed_size) {
    return 0;
}

int ocall_print_credentials(const char* service, const char* username, const char* password) {
    return 0;
}

int ocall_wallet_exists(void) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) {
        return 0;
    }
    file.close();
    return 1;
}

int ocall_get_wallet_size(size_t* wallet_size) {
    return 0;
}


