# PV204_area51 Project

A simple interactive command-line password vault based on Intel SGX.

For academic purposes only. Do not use it as storage for sensitive data!

## Requirements

- Linux OS
- Hardware SGX support with the appropriate [driver](https://github.com/intel/linux-sgx-driver) or an [SGX emulator](https://github.com/sslab-gatech/opensgx)

## Installation

1. Clone the project using `$ git clone https://github.com/addam128/PV204_area51.git`.
2. Open the Makefile and change the value of `SGX_SDK ?=` to the location of your sgxsdk directory.
3. Compile the project using `$ make`.
4. Add the `lib64` directory location (inside the sgxsdk directory) to the environment variable: `$ export LD_LIBRARY_PATH=<path>`.
5. Run the application with `$ ./area51`.

## Usage

- The command line interface is interactive. The command `help` lists all possible commands.
- Users can create multiple vaults protected by master passwords.
- Each vault can save username-password pairs for a service.
- Multiple accounts can be saved for every service.
- Each vault can store 100 entries.
- Passwords must be between 8 and 62 chars long.
- The maximal length for service names and usernames is 128 chars.

### List of commands

Command | Description
------- | -----
help | Lists all possible commands.
new | Creates a new password vault.
add | Adds a new entry to a password vault.
remove | Removes an en existing entry from a vault.
change_service | Changes the password for a service.
list | Lists all saved service-username pairs from a vault.
search | Lists all saved usernames for a given service.
change | Changes the master password of a vault.
choose | Choose another vault.
exit | Exit the application.
