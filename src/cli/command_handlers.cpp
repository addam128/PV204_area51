#include "command_handlers.hpp"

namespace commands {

    void list() {
       
        Prompter service_p = Prompter();
        service_p.with_prompt("Service to search for:")
                 .interact();
        try {
            Password mp = Password();
            mp.with_prompt("Master password:")
              .interact();

        } catch (const std::bad_alloc& ex) {
            std::cerr << "Could not get that, sorry." << ex.what() << std::endl;
            return ;
        } catch (...) {
            std::cerr << "other error" << std::endl;
        }

        //vec =  ecall_list(service_p.c_str(), mp.c_str());
        // print em'
    }


    void change_master() {
       
        try {
           
            Password old_mp = Password();
            Password new_mp = Password();

            old_mp.with_prompt("Old master password:")
                  .interact();

            new_mp.with_prompt("New master password:")
                  .with_confirmation("Repeat new master password",
                   "Passwords do not match")
                  .interact();

        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }

        //ecall_change_master(old_mp.c_str(), new_mp.c_str())
    }



    void new_entry() {

        Prompter service_p = Prompter();
        Prompter user_p = Prompter();
        
        service_p.with_prompt("For service:")
                 .interact();

        user_p.with_prompt("For username:")
              .interact();

        std::cout << service_p.c_str() << " " << user_p.c_str() << std::endl; 

        try {

            Password service_pwd = Password();
            Password master_pwd = Password();

            service_pwd.with_prompt("Service password:")
                     .with_confirmation("Repeat service password:",
                     "Passwords do not match.")
                     .interact();

            master_pwd.with_prompt("Master password:")
                      .interact();
        } catch (const std::bad_alloc& ex) {
            std::cerr << "Could not get that, sorry." << ex.what() << std::endl;
            return ;
        } catch (...) {
            std::cerr << "other error" << std::endl;
        }

        /*ecall_new_entry(
            service_p.c_str(),
            user_p.c_str(),
            service_pwd.c_str(),
            master_pwd.c_str()
        );*/
    }


    void remove_entry() {

        Prompter service_p = Prompter();
        Prompter user_p = Prompter();
        
        service_p.with_prompt("For service:")
                 .interact();

        user_p.with_prompt("For username:")
              .interact();

        try {
            
            Password master_pwd = Password();

            master_pwd.with_prompt("Master password:")
                      .interact();
        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }

        /*ecall_remove_entry(
            service_p.c_str(),
            user_p.c_str(),
            master_pwd.c_str()
        );*/
    }

    void create_facility() {
        
        try {
            
            Password master_pwd = Password();

            master_pwd.with_prompt("Master password for new facility:")
                      .with_confirmation("Repeat master password",
                       "Passwords do not match")
                       .interact();
        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }

        //ecall_new_facility(master_pwd.c_str());
    }

    void print_help() {
        std::cout << "Available commands:\n"
                    << "\tnew - create new password vault\n"
                    << "\tadd - add new password to vault\n"
                    << "\tremove - remove password entry from vault\n"
                    << "\tlist - show availablle usernames for given service\n"
                    << "\tchange - change the master password\n"
                    << "\texit - exit program\n";
    }
}