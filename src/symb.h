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

#ifndef STAN_SYM_H
#define STAN_SYM_H

#define STAN_SYM_TYPE_NONE    0
#define STAN_SYM_TYPE_SECTION 1
#define STAN_SYM_TYPE_FUNC    2
#define STAN_SYM_TYPE_LABEL   4

// This is also a STAN_ITEM object
typedef struct stan_sym_t
{
  long addr;   // Memory address
  char *id;    // Symbol name
  int  dump;
  int  type; 
  void *p;
} STAN_SYM;

#ifdef __cplusplus
extern "C" {
#endif

  // Symbol object
  STAN_SYM*   stan_sym_new (char *id, long addr);
  int         stan_sym_free (STAN_SYM *s);
  STAN_SYM*   stan_sym_clone (STAN_SYM *s);
  
  // XXX: To be removed???
  int         stan_sym_set_id (STAN_SYM *s, char *id);
  int         stan_sym_set_data (STAN_SYM *s, void *p);
  void*       stan_sym_get_data (STAN_SYM *s);
  int         stan_sym_add_type (STAN_SYM *s, int type);
  
#ifdef __cplusplus
}
#endif


#endif
