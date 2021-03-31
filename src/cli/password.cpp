#include "password.hpp"

int Password::read_pwd(char* buffer) {

/* https://www.gnu.org/software/libc/manual/html_node/getpass.html */
    struct termios old_t, new_t;

    /* Turn echoing off and fail if we can’t. */
   if (tcgetattr (fileno (stdin), &old_t) != 0)
        return -1;

    new_t = old_t;
    new_t.c_lflag &= ~ECHO;
    if (tcsetattr (fileno (stdin), TCSAFLUSH, &new_t) != 0)
        return -1;

    std::memset(buffer, 0 , MAX_PWD_LEN * sizeof(char));
    

    /* Read the passphrase */
    if (fgets(buffer, MAX_PWD_LEN, stdin) == nullptr) {
        return -1;
    }

    /* Restore terminal. */
    (void) tcsetattr (fileno (stdin), TCSAFLUSH, &old_t);


    return 0;
}

const Password& Password::interact() {

    std::cout << _prompt << std::endl;
    if (read_pwd(_pwd) < 0) {
        throw new std::ios_base::failure("whoops");
    }
    if (_confirm_flag) {
        std::cout << _confirmation_prompt << std::endl;
        if (read_pwd(_confirm_pwd) < 0) {
            throw new std::ios_base::failure("whoops");
        }
        if (!(sodium_memcmp(_pwd, _confirm_pwd, MAX_PWD_LEN) != -1)) {
            std::cout << _confirm_error << std::endl;
            throw new NotMatchingError(_confirm_error);
        }
        sodium_memzero(_confirm_pwd, MAX_PWD_LEN);
    }

    return *this;
}