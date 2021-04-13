#pragma once

#include "prompt.hpp"
#include "command_handlers.hpp"


class Term {
public:
    static void spawn(sgx_enclave_id_t eid) {
        Prompter p = Prompter();
        p.with_prompt("Area51 $>: ");
        for (;;) {
            try {
                p.interact();

                if (p.answer() == "new") 
                    commands::create_facility(eid);
                else if (p.answer() == "add") 
                    commands::new_entry(eid);
                else if (p.answer() == "remove")
                    commands::remove_entry(eid);
                else if (p.answer() == "change")
                    commands::change_master(eid);
                else if (p.answer() == "list")
                    commands::list(eid);
                else if (p.answer() == "search")
                    commands::search(eid);
                else if (p.answer() == "exit")
                    return;
                else if (p.answer() == "help")
                    commands::print_help();
                else
                    std::cout << "Unknown option." << std::endl;
            
            } catch(const std::bad_alloc& ex) {
                std::cerr << "Could not get memory, exiting." << ex.what() << std::endl;
                return;
            } catch (const std::ios_base::failure& ex) {
                std::cerr << ex.what() << std::endl;
                return;
            }
            catch (const PwdTooShort& ex) {
                std::cerr << ex.what() << std::endl;
            }
            catch (const NotMatchingError& ex) {
                std::cerr << ex.what() << std::endl;
            }
            catch (...) {
                std::cerr << "Unknown error, exiting." << std::endl;
                return;
            }

            p.clear_answer();
        }
    }
};