#pragma once

#include <stdio.h>
#include <string>
#include <iostream>

#include "constants.hpp"


namespace utils {
    void print_error(std::string& error);
    int is_error(int error_code);
}