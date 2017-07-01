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

/*
 * A case is a project you are working on!
 *
 */

#ifndef STAN_CASE_H
#define STAN_CASE_H

#include "core.h"

typedef struct stan_case_t
{
  char         *id;    // User provided name
  int           dirty; // Did it change... do we need to save?
  STAN_CORE    *k;  // The core you are working on
} STAN_CASE;


#ifdef __cplusplus
extern "C" {
#endif

  STAN_CASE *stan_case_new                 (char *id);
  int        stan_case_free                (STAN_CASE *c);

  int        stan_case_dump                (STAN_CASE *c);
  
  int        stan_case_changed             (STAN_CASE *c);
  int        stan_case_set_core            (STAN_CASE *c, STAN_CORE *k);
  int        stan_case_set_core_from_file  (STAN_CASE *c, char *fname);
  // For future implementation
  int        stan_case_save                (STAN_CASE *c, char *fname, int patch);
  STAN_CASE *stan_case_load                (STAN_CASE *c, char *fname);

#ifdef __cplusplus
}
#endif

#endif
