#pragma once

#include "prompt.hpp"
#include "command_handlers.hpp"


class Term {
public:
    static void spawn() {
        Prompter p = Prompter();
        p.with_prompt("Area51 $>: ");
        for (;;) {
            p.interact();

            if (p.answer() == "new") 
                commands::create_facility();
            else if (p.answer() == "add") 
                commands::new_entry();
            else if (p.answer() == "remove")
                commands::remove_entry();
            else if (p.answer() == "change")
                commands::change_master();
            else if (p.answer() == "list")
                commands::list();
            else if (p.answer() == "exit")
                return;
            else
                std::cout << "Unknown option." << std::endl;
            p.clear_answer();
        }
    }
};