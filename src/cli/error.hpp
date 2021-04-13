#pragma once

#include <exception>
#include <string>
#include <strstream>
#include "constants.hpp"


class NotMatchingError : public std::exception {
private:
    std::string _msg;

public:

    NotMatchingError(std::string msg): _msg(std::move(msg)){}

    virtual const char* what() const noexcept override {
        return _msg.c_str();
    }

};


class PwdTooShort : public std::exception {
private:
    std::string _msg;

public:

    PwdTooShort(std::string msg): _msg(std::move(msg + std::to_string(MIN_PWD_LEN) + std::string(" chars."))){}

    virtual const char* what() const noexcept override {
        return _msg.c_str();
    }

};