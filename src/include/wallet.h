#ifndef PV204_AREA51_WALLET_H
#define PV204_AREA51_WALLET_H

#include <string>
#include <vector>

struct Entry {
    std::string service;
    std::string username;
    std::string password;
};

struct Wallet {
    size_t number_of_entries;
    std::vector <Entry> entries;
    std::string master_password;
}

#endif //PV204_AREA51_WALLET_H
