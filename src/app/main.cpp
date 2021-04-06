#include <sodium.h>
#include "../cli/password.hpp"
#include "../cli/error.hpp"
#include <sodium.h>
#include "../cli/terminal.hpp"

int main() {
    if (sodium_init() < 0) {
        std::cerr << "panic! Could not init crypto library, exiting!" << std::endl;
        exit(1);
    }

    Term::spawn();

    

}