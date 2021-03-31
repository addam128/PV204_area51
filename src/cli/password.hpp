#pragma once

#include <iostream>
#include <termios.h>
#include <cstring>
#include <stdio.h>
#include <wchar.h>
#include <sodium.h>

#include "no_match_err.hpp"

const int MAX_PWD_LEN = 256;

class Password {

private:
    char* _pwd;
    char* _confirm_pwd;
    std::string _prompt;
    std::string _confirmation_prompt;
    std::string _confirm_error;
    bool _confirm_flag;

    int read_pwd(char*);

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