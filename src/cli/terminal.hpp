#pragma once

#include "prompt.hpp"
#include "command_handlers.hpp"


class Term {
public:
    static void spawn(sgx_enclave_id_t eid) {
        Prompter p = Prompter();
        p.with_prompt("Area51 $>: ");
        for (;;) {
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
            p.clear_answer();
        }
    }
};