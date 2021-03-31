#include <sodium.h>
#include "cli/password.hpp"
#include "cli/no_match_err.hpp"
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        std::cerr << "panic! Could not init crypto library, exiting!" << std::endl;
        exit(1);
    }
    try {
        Password pwd = Password();
        pwd.with_prompt("Master password:")
           .with_confirmation("Repeat password:", "Passwords do not match!")
           .interact();

        std::cout << pwd.c_str() << std::endl;
    } catch (...) {
        std::cerr << "exception thrown" << std::endl;
    }

}