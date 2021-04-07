#include "command_handlers.hpp"

namespace commands {

    void list(sgx_enclave_id_t eid) {
        try {
            
            Password master_pwd = Password();

            master_pwd.with_prompt("Master password:")
                       .derive(true)
                       .interact();

            int retval = 0;
            sgx_status_t enclave_status = ecall_list_vault(eid, &retval, master_pwd.c_str());

            printf("%d", retval);

        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }
    }
    

    void search(sgx_enclave_id_t eid) {
       
        Prompter service_p = Prompter();
        service_p.with_prompt("Service to search for:")
                 .interact();
        try {
            Password mp = Password();
            mp.with_prompt("Master password:")
              .derive(true)
              .interact();

            int retval = 0;
            sgx_status_t enclave_status = ecall_list_entry(
                eid, &retval, mp.c_str(),  service_p.c_str());

            printf("%d", retval);

        } catch (const std::bad_alloc& ex) {
            std::cerr << "Could not get that, sorry." << ex.what() << std::endl;
            return ;
        } catch (...) {
            std::cerr << "other error" << std::endl;
        }
    }


    void change_master(sgx_enclave_id_t eid) {
       
        try {
           
            Password old_mp = Password();
            Password new_mp = Password();

            old_mp.with_prompt("Old master password:")
                  .derive(true)
                  .interact();

            new_mp.with_prompt("New master password:")
                  .with_confirmation("Repeat new master password",
                   "Passwords do not match")
                   .derive(true)
                   .interact();
            
            int retval = 0;
            sgx_status_t enclave_status = ecall_change_master_password(
                eid, &retval, old_mp.c_str(), new_mp.c_str()); // TODO error handling

        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }
    }



    void new_entry(sgx_enclave_id_t eid) {

        Prompter service_p = Prompter();
        Prompter user_p = Prompter();
        
        service_p.with_prompt("For service:")
                 .interact();

        user_p.with_prompt("For username:")
              .interact();
 

        try {

            Password service_pwd = Password();
            Password master_pwd = Password();

            service_pwd.with_prompt("Service password:")
                     .with_confirmation("Repeat service password:",
                     "Passwords do not match.")
                     .interact();

            master_pwd.with_prompt("Master password:")
                      .derive(true)
                      .interact();

            int retval = 0; 
            sgx_status_t enclave_status = ecall_add_entry(
                eid,
                &retval,
                master_pwd.c_str(),
                service_p.c_str(),
                user_p.c_str(),
                service_pwd.c_str()
            );

            printf("%d", retval);
        } catch (const std::bad_alloc& ex) {
            std::cerr << "Could not get that, sorry." << ex.what() << std::endl;
            return ;
        } catch (...) {
            std::cerr << "other error" << std::endl;
        }
    
    }


    void remove_entry(sgx_enclave_id_t eid) {

        Prompter service_p = Prompter();
        Prompter user_p = Prompter();
        
        service_p.with_prompt("For service:")
                 .interact();

        user_p.with_prompt("For username:")
              .interact();

        try {
            
            Password master_pwd = Password();

            master_pwd.with_prompt("Master password:")
                      .derive(true)
                      .interact();
                
            int retval = 0;
            /*sgx_status_t enclave_status = ecall_remove_entry(
                eid,
                &retval,
                service_p.c_str(),
                user_p.c_str(),
                master_pwd.c_str()
            );*/                                       //unimplemented!
        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }
    }

    void create_facility(sgx_enclave_id_t eid) {
        
        try {
            
            Password master_pwd = Password();

            master_pwd.with_prompt("Master password for new facility:")
                      .with_confirmation("Repeat master password:",
                       "Passwords do not match")
                       .derive(true)
                       .interact();

            int retval = 0;
            sgx_status_t enclave_status = ecall_create_vault(eid, &retval, master_pwd.c_str());

            printf("%d", retval);

        } catch (...) {
            std::cerr << "Could not get that, sorry." << std::endl;
            return ;
        }
    }

    void print_help() {
        std::cout << "Available commands:\n"
                    << "\tnew - create new password vault\n"
                    << "\tadd - add new password to vault\n"
                    << "\tremove - remove password entry from vault\n"
                    << "\tlist - show all service-username pairs\n"
                    << "\tsearch - show availablle usernames for given service\n"
                    << "\tchange - change the master password\n"
                    << "\texit - exit program\n";
    }
}