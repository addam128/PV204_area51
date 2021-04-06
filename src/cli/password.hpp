#pragma once

#include <limits>
#include <iostream>
#include <termios.h>
#include <cstring>
#include <stdio.h>
#include <wchar.h>
#include <sodium.h>

#include "error.hpp"
#include "constants.hpp"


class Password {

private:
    char* _pwd;
    char* _confirm_pwd;
    std::string _prompt;
    std::string _confirmation_prompt;
    std::string _confirm_error;
    bool _confirm_flag;
    bool _derivation_needed;

    int read_pwd(char*); // could be friend function, but meh

public:
    Password():
        _prompt(),
        _confirmation_prompt(),
        _confirm_error(),
        _confirm_flag(false) 
    {
       
        _pwd = (char*)sodium_allocarray(MAX_PWD_LEN + 1, sizeof(char));
        _confirm_pwd = (char*)sodium_allocarray(MAX_PWD_LEN + 1, sizeof(char));
        if (_pwd == nullptr || _confirm_pwd == nullptr) {
            throw new std::bad_alloc;
        }
        std::memset(_pwd, 0, MAX_PWD_LEN + 1); 
        std::memset(_confirm_pwd, 0, MAX_PWD_LEN + 1); 
    };

    ~Password() {
       
        sodium_memzero(_pwd, (MAX_PWD_LEN + 1) * sizeof(char));
        sodium_memzero(_confirm_pwd, (MAX_PWD_LEN + 1) * sizeof(char));
        sodium_free(_confirm_pwd);
        sodium_free(_pwd);
    }

    inline Password& with_prompt(std::string promptval) {
      
        _prompt = std::move(promptval);
        return *this;
    }

    inline Password& derive(bool val) {
        _derivation_needed = val;
        return *this;
    }

    inline Password& with_confirmation(std::string confirm_txt, std::string confirm_err) {
        
        _confirm_flag = true;
        _confirmation_prompt = std::move(confirm_txt);
        _confirm_error = std::move(confirm_err);
        return *this;
    }

    const Password& interact();

    const char* c_str() const {
       
        return _pwd;
    }



};