/*
  STAN STAN is a sTAtic aNalyser
  Copyright (c) 2017 pico

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/* Symbol Management
 * ---------------------------------------
 */

#ifndef STAN_FUNC_H
#define STAN_FUNC_H

#include <capstone/capstone.h>
#include "core.h"
#include "symb.h"

#define STAN_FUNC_NOT_INIT  0
#define STAN_FUNC_INIT      1

/* ***********************************
   Function are just special Symbols that holds extra information
   The extra information is stored in the symbol private area
   When disassembling a function
   - If the function data structures have already been initialised... show them
   - Otherwise, produce data structures and them show them
   Use can edit information
 */

typedef struct stan_lsym_t
{
  int   off;     // Local vars and params are stored in stack
  char  *name;            // user assigned name
} STAN_LSYM;

typedef struct stan_func_t
{
  STAN_SYM    *s;      // Back pointer to associated symbol
  int         flag;   // Function state
  long        start;  // Function start address
  long        end;    // Function end address
  cs_insn     *ins;
  STAN_IMETA  *imeta; // Function metadata
  size_t      count;  // Size of imeta array
  STAN_LSYM   *lsym; // Table of local symbols (local vars and paramas)
  int         n_lsym;
} STAN_FUNC;

#ifdef __cplusplus
extern "C" {
#endif

  // Symbol object
  STAN_FUNC*   stan_func_new (STAN_SYM *s);
  int          stan_func_free (STAN_FUNC *f);
  int          stan_func_clear (STAN_FUNC *f);

  int          stan_func_set_end (STAN_FUNC *f, long end);
  int          stan_func_set_state (STAN_FUNC *f, int flag);
  STAN_LSYM*   stan_func_get_lsym (STAN_FUNC *f, int off);
  int          stan_func_add_lsym (STAN_FUNC *f, char *name, int off);
  int          stan_func_rename_lsym (STAN_FUNC *f, char *old_name, char *new_name);
  
#ifdef __cplusplus
}
#endif


#endif
