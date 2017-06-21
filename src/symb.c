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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "symb.h"
#include "utils.h"

// Symbol object
STAN_SYM*  
stan_sym_new (char *id, long addr)
{
  STAN_SYM  *s;

  if ((s = malloc (sizeof(STAN_SYM))) == NULL)
    {
      fprintf (stderr, "- Cannot allocate memory for symbol\n");
      return NULL;
    }
  memset (s, 0, sizeof(STAN_SYM));
  s->addr = addr;
  if (id)
    s->id = strdup (id);
  else
    s->id = strdup ("NONAME");

  s->type = STAN_SYM_TYPE_NONE;
  return s;
}

int         
stan_sym_free (STAN_SYM *s)
{
  if (!s) return -1;

  if (s->id) free (s->id);
  //memset (s, 0, sizeof(STAN_SYM));
  free (s);

  return 0;
}

STAN_SYM*   
stan_sym_clone (STAN_SYM *s)
{
  STAN_SYM *c;

  if (!s) return NULL;
  c = stan_sym_new (s->id, s->addr);
  c->type = s->type;
  return c;
}
// XXX: To be removed???
int         
stan_sym_set_data (STAN_SYM *s, void *p)
{
  if (!s) return -1;

  s->p = p; // Allow NULLs

  return 0;
}

void*       
stan_sym_get_data (STAN_SYM *s)
{
  if (!s) return NULL;
  return s->p;
}


int         
stan_sym_set_id (STAN_SYM *s, char *id)
{
  if (!s) return -1;
  if (!id) return -1;

  if (s->id) free (s->id);
  s->id = strdup (id);
  return 0;
}

int         
stan_sym_add_type (STAN_SYM *s, int type)
{
  if (!s) return -1;
  s->type |= type;
  return 0;
}



