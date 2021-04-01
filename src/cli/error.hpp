#pragma once

#include <exception>
#include <string>


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

    PwdTooShort(std::string msg): _msg(std::move(msg)){}

    virtual const char* what() const noexcept override {
        return _msg.c_str();
    }

};