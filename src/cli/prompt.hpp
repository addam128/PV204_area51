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
        std::string answer;
        std::cout << _prompt << std::flush;
        std::getline(std::cin, answer);
        _answer = answer.substr(0, MAX_SERVICE_N_USER_LEN);
        return *this;
    }

    void clear_answer() {
       
        _answer.clear();
    }

    void answer_push(const std::string& to_add) {

        _answer += to_add;
    }

    const char* c_str() const {
        
        return _answer.c_str();
    }

    const std::string& answer() {
        return _answer;
    }

};