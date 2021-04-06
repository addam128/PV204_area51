#include "password.hpp"


/* https://www.gnu.org/software/libc/manual/html_node/getpass.html */
int Password::read_pwd(char* buffer) {

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

    std::cout << _prompt << std::flush;
    if (read_pwd(_pwd) < 0) {
        throw new std::ios_base::failure("whoops");
    }
    if (std::strlen(_pwd) < MIN_PWD_LEN) {
        std::cout<< _pwd << std::endl;
        throw new PwdTooShort("The password is not long enough");
    }
    std::cout << std::endl;
    if (_confirm_flag) {
        std::cout << _confirmation_prompt << std::flush;
        if (read_pwd(_confirm_pwd) < 0) {
            throw new std::ios_base::failure("whoops");
        }
        if (std::strlen(_confirm_pwd) < MIN_PWD_LEN) {
        throw new PwdTooShort("The password is not long enough");
    }
        std::cout << std::endl;
        if (!(sodium_memcmp(_pwd, _confirm_pwd, MAX_PWD_LEN) != -1)) {
            std::cout << _confirm_error << std::endl;
            throw new NotMatchingError(_confirm_error);
        }
        sodium_memzero(_confirm_pwd, MAX_PWD_LEN);
    }
    if (_derivation_needed) {

        byte* salt = (byte*)sodium_allocarray(crypto_pwhash_SALTBYTES, 1);
        byte* to_store = (byte*)sodium_allocarray(MASTER_HASH_LEN + 1, 1);
        std::memset(to_store, 0 ,MASTER_HASH_LEN + 1);

        crypto_generichash(salt, crypto_pwhash_SALTBYTES,
        (byte*)_pwd, std::strlen(_pwd), nullptr, 0);

        if (0 != crypto_pwhash(to_store, MASTER_HASH_LEN,
        (const char*)_pwd, std::strlen(_pwd),  salt,
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_DEFAULT)) {
            throw new std::bad_alloc;
        }

        sodium_memzero(salt, crypto_pwhash_SALTBYTES);
        sodium_memzero(_pwd, MAX_PWD_LEN + 1);

        sodium_free(salt);
        sodium_free(_pwd);

        _pwd = (char*)to_store;
    }

    return *this;
}