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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "symb.h"
#include "func.h"

STAN_FUNC*   
stan_func_new (STAN_SYM *s)
{
  STAN_FUNC  *f;

  if (!s) return NULL;
  if ((f = (STAN_FUNC*) malloc (sizeof(STAN_FUNC))) == NULL) return NULL;
  memset (f, 0, sizeof(STAN_FUNC));
  // Initialise function
  f->s = s;
  f->flag = STAN_FUNC_NOT_INIT;
  f->start = s->addr;
  f->count = 0;
  f->n_lsym = 0;

  // Add this info to the current symbol
  stan_sym_set_data (s, f);

  return f;
}

int          
stan_func_free (STAN_FUNC *f)
{
  int   i;

  if (!f) return -1;

  // Free imeta
  if (f->imeta) free (f->imeta);
  // Free localsymb
  if (f->lsym)
    {
      for (i = 0; i < f->n_lsym; i++)
	if (f->lsym[i].name) free (f->lsym[i].name);
      free (f->lsym);
    }
  // Unlink from associated symbol
  stan_sym_set_data (f->s, NULL);
  free (f);
 
  return 0;
}


/* Deletes all associated data but not the main object */
int          
stan_func_clear (STAN_FUNC *f)
{
  int   i;

  if (!f) return -1;

  // Free imeta
  if (f->imeta) free (f->imeta);
  // Free localsymb
  if (f->lsym)
    {
      for (i = 0; i < f->n_lsym; i++)
	if (f->lsym[i].name) free (f->lsym[i].name);
      free (f->lsym);
    }
  f->imeta = NULL;
  f->lsym = NULL;
  f->count = 0;
  f->n_lsym = 0;
  f->flag = STAN_FUNC_NOT_INIT;
 
  return 0;
}


int          
stan_func_set_end (STAN_FUNC *f, long end)
{
  if (!f) return -1;
  if (end < f->start) return -1;
  f->end = end;
  return 0;
}

int          
stan_func_set_state (STAN_FUNC *f, int flag)
{
  if (!f) return -1;
  f->flag = flag;
  return 0;
}

STAN_LSYM*
stan_func_get_lsym (STAN_FUNC *f, int off)
{
  int i, n;
  
  if (!f) return 0;
  n = f->n_lsym;
  for (i = 0; i < n; i++)
    if (f->lsym[i].off == off) return &f->lsym[i];

  return NULL;
}

STAN_LSYM*
stan_func_get_lsym_by_name (STAN_FUNC *f, char *name)
{
  int i, n;
  
  if (!f) return 0;
  n = f->n_lsym;
  for (i = 0; i < n; i++)
    if (!strcmp (f->lsym[i].name, name)) return &f->lsym[i];

  return NULL;
}


int          
stan_func_add_lsym (STAN_FUNC *f, char *name, int off)
{
  STAN_LSYM  *t, *aux;
  int         n;
 
  if (!f) return -1;
  if (!name) return -1;

  // Check if symbol already exists....

  // Add entry for the new symbol
  t = f->lsym;
  n = f->n_lsym;
  if ((aux = realloc (t, sizeof(STAN_LSYM) * (n + 1))) == NULL) return -1;
  f->lsym = aux;

  f->lsym[n].off = off;
  f->lsym[n].name = strdup (name);
  f->n_lsym ++;
  
  return 0;
}

int          
stan_func_rename_lsym (STAN_FUNC *f, char *old_name, char *new_name)
{
  STAN_LSYM *s;

  if (!f) return -1;
  if (!old_name) return -1;
  if (!new_name) return -1;

  if (!(s = stan_func_get_lsym_by_name (f, old_name))) return -1;

  if (s->name) free (s->name);
  s->name = strdup (new_name);

  return 0;
}

  
