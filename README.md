# STAN
STAN is a sTAtic aNalyser. It is my pet project to learn about reverse engineering.

It is in alpha phase and it may crash at any point... but it is usable for simple projects...

## Features

* Support 32 and 64 bits ELF binaries
* Support x86 (32/64bits) and ARM (32bits)
* Analysis capabilities
  - Automatically create function objects out of CALL mnemonics
  - Automatically create label objects out of JX mnemonics
  - Resolve IP relative addressing
  - Shows data when it is printable
* More to come


# Dependencies
STAN uses capstone (http://www.capstone-engine.org/) for its disassembling needs

# Installation

`./configure; make; make install` ... I guess :)

# Commands

This is the list of current available commands

* __case.dump__. Dumps information about the current case/project
* __case.save__. Saves the current case. It will save the status in a file named against the binary loaded with the extension .srep
* __case.load__ `file.srep`. Loads a previously saved case. 
* __core.info__. Dumps  information about the current binary being analysed
* __core.symbol__. Dumps the symbols of the binary being analysed
* __core.functions__. Dumps the sumbols that STAN belives are functions
* __core.labels__. Dumps the identified labels
* __core.load__ `file`. Loads the binary specified by `file`
* __dis.section__ `section_name`. Disassembles a whole section
* __dis.function__ `function_name`. Disassembles a function. You can define functions using `func.def` in case the analysis failed.
* __dis.addr__ `addr icount`. Disassembles `iconunt` instructions from the specified address.
* __func.rename__ `old_function_name` `new_function_name`. Renames a function
* __func.def__ `func_name` `address`. Tells STAN that there is a function at `address`
* __label.rename__ `old_label_name` `new_label_name`. Renames a lable
* __label.gen_table__ `prefix addr count`. Generates label `prefix_X` for `count` pointer in a pointer table at `addr`
* __comment.add__ `address` `Comment`. Adds a comment at a given address. Address has to be hexadecimal without `0x` at the beginning
* __comment.del__ `address`. Deletes a comment associated to a given address
* __mem.dump__ `fmt` `address` `count`. Dumps `count` items from memory at `address`. Valid formats are `x` for hex bytes and `p` for pointers... more to come
* __mem.poke__ `fmt` `address` `string`. Writes the specified string at address `addr`. Valid formats are `x` for hex bytes. 
* __sym.def__ `sym_name` `address`. Defines a generic symbol at `address`
* __help__. Shows help
* __help.abi__. Shows the function calling convention for the binary being analysed
* __quit__. Do not leave STAN alone!!!!

You can use TAB autocompletion to figure out the commands. Segments, Functions and Labels are also autocompleted when available. Typinh a command with the wrong syntax will show the associated help

