#include "utils.hpp"

namespace utils {
    void print_error(std::string& error) {
        std::cerr << "[ERROR] " << error << std::endl;
    }

    int is_error(int error_code) {
        std::string error_message;
        switch (error_code) {
            case RET_SUCCESS:
                return 0;
            case ERR_VAULT_ALREADY_EXISTS:
                error_message = "Given vault already exists.";
                break;
            case ERR_INVALID_MASTER_PASSWORD:
                error_message = "Invalid password.";
                break;
            case ERR_VAULT_FULL:
                error_message = "Vault is full.";
                break;
            case ERR_CANNOT_SEAL_VAULT:
                error_message = "Cannot seal the vault.";
                break;
            case ERR_CANNOT_SAVE_TO_FILE:
                error_message = "Cannot save vault to file.";
                break;
            case ERR_CANNOT_LOAD_FROM_FILE:
                error_message = "Cannot load vault from file.";
                break;
            case ERR_CANNOT_UNSEAL_VAULT:
                error_message = "Cannot unseal the vault.";
                break;
            case ERR_SERVICE_USERNAME_NOT_FOUND:
                error_message = "Given service/username pair not found in the vault.";
                break;
            default:
                error_message = "Unknown error.";
        }
        print_error(error_message);
        return 1;
    }
}

