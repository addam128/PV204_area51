#include <cstring>
#include <fstream>

int ocall_save_wallet(const uint8_t* sealed_data, size_t sealed_size) {

}

int ocall_load_wallet(uint8_t* sealed_data, size_t sealed_size) {

}

int ocall_print_credentials(const Entry* entry);

int ocall_is_wallet(void) {
    ifstream file(WALLET_FILE, ios::in | ios::binary);
    if (file.fail()) {
        return 0;
    }
    file.close();
    return 1;
}


