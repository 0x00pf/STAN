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

* case.dump. Dumps information about the current case/project
* case.save. Saves the current case. It will save the status in a file named against the binary loaded with the extension .srep
* case.load `file.srep`. Loads a previously saved case. 
* core.info. Dumps  information about the current binary being analysed
* core.symbol. Dumps the symbols of the binary being analysed
* core.functions. Dumps the sumbols that STAN belives are functions
* core.labels. Dumps the identified labels
* core.load `file`. Loads the binary specified by `file`
* dis.section `section_name`. Disassembles a whole section
* dis.function `function_name`. Disassembles a function. You can define functions using `func.def` in case the analysis failed.
* func.rename `old_function_name` `new_function_name`. Renames a function
* func.def `func_name` `address`. Tells STAN that there is a function at `address`
* label.rename `old_label_name` `new_label_name`. Renames a lable
* comment.add `address` `Comment`. Adds a comment at a given address. Address has to be hexadecimal without `0x` at the beginning
* comment.del `address`. Deletes a comment associated to a given address
* mem.dump `fmt` `address` `count`. Dumps `count` items from memory at `address`. Valid formats are `x` for hex bytes and `p` for pointers... more to come
* sym.def `sym_name` `address`. Defines a generic symbol at `address`
* help.abi. Shows the function calling convention for the binary being analysed
* quit. Do not leave STAN alone!!!!



