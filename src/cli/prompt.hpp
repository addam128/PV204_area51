#pragma once 

#include <iostream>
#include <iomanip>
#include <limits>

#include "constants.hpp"

class Prompter {
private:
    std::string _prompt;
    std::string _answer;

public:

    Prompter(): _prompt(), _answer() {}

    inline Prompter& with_prompt(std::string prompt) {
      
        _prompt = std::move(prompt);
        return *this;
    }

    const Prompter& interact() {
       
        std::cout << _prompt << std::flush;
        std::getline(std::cin, _answer);
        return *this;
    }

    void clear_answer() {
       
        _answer.clear();
    }

    const char* c_str() const {
        
        return _answer.c_str();
    }

    const std::string& answer() {
        return _answer;
    }

};