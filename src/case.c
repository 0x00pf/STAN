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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#include "case.h"
#include "core.h"
#include "dis.h"
#include "symb.h"
#include "func.h"
#include "utils.h"

/* Constructor/Destructor */
STAN_CASE *
stan_case_new (char *id)
{
  STAN_CASE *c;

  if ((c = malloc (sizeof(STAN_CASE))) == NULL)
    {
      fprintf (stderr, "Cannot allocate memory for case\n");
      return NULL;
    }
  if (!id) c->id = strdup ("corpse");
  else c->id = strdup (id);

  c->k = NULL;

  return c;
}

int        
stan_case_free (STAN_CASE *c)
{
  if (!c) return -1;
  if (c->id) return -1;

  free (c->id);
  stan_core_free (c->k);
  free (c);

  return 0;
}

int
stan_case_dump (STAN_CASE *c)
{
  if (!c) return -1;
  printf ("--------------------------------------\n");
  printf ("CASE: '%s'\n", c->id);
  if (!c->k)
    {
      fprintf (stderr, "- No core set for this case\n");
      return -1;
    }
  printf ("CORE: %p\n", c->k);
  printf ("......................................\n");
  stan_core_dump (c->k);
  printf ("--------------------------------------\n");
  return 0;
}

/* Accessors */

// probably remove this one!!!
int        
stan_case_changed (STAN_CASE *c)
{
  if (!c) return -1;
  c->dirty = 1;
  // 
  return 0;
}

int        
stan_case_set_core (STAN_CASE *c, STAN_CORE *k)
{
  if (!c) return -1;
  if (!k) return -1;

  c->k = k;

  return 0;
}

int        
stan_case_set_core_from_file (STAN_CASE *c, char *fname)
{
  if (!c) return -1;

  return 0;
}

// For future implementation
int
stan_case_save (STAN_CASE *c, char *fname, int patch)
{
  FILE         *f;
  int          i, j, n;
  STAN_SYM     *s;
  STAN_FUNC    *_f;
  STAN_COMMENT *com;

  char *fname1;

  if (!c) return -1;

  n = strlen (c->k->fname);
  fname1 = malloc (n + 6);
  sprintf (fname1, "%s.srep", c->k->fname);

  if ((f = fopen (fname1, "wt")) == NULL)
    {
      fprintf (stderr, "- Cannot save to file '%s'\n", fname1);
      return -1;
    }

  // Dump Renamed Symbols
  n = c->k->sym->n;
  for (i = 0; i < n; i++)
    {
      s = (STAN_SYM*) c->k->sym->p[i];
      if (s->dump)
	fprintf (f, "S:%s:%p\n", s->id, (void*)s->addr);
      if (s->p) // If private data is set)
	{
	  _f = (STAN_FUNC*)s->p;
	  fprintf (f, "D:%s:%p:%p\n", s->id, _f->start, _f->end);
	  for (j = 0; j < _f->n_lsym; j++)
	    {
	      if (strcmp (_f->lsym[j].id, _f->lsym[j].name))
		fprintf (f, "V:%s:%s:%s\n", 
			 s->id, _f->lsym[j].id, _f->lsym[j].name);
	    }
	}
    }
  // Dump Renamed Labels
  n = c->k->label->n;
  for (i = 0; i < n; i++)
    {
      s = (STAN_SYM*)c->k->label->p[i];
      if (s->dump)
	fprintf (f, "L:%s:%p\n", s->id, (void*)s->addr);
    }
  // Dump Renamed Functions
  n = c->k->func->n;
  for (i = 0; i < n; i++)
    {
      s = (STAN_SYM*)c->k->func->p[i];
      if (s->dump)
	fprintf (f, "F:%s:%p\n", s->id, (void*)s->addr);
    }
  // Dump Comments
  n = c->k->comment->n;
  for (i = 0; i < n; i++)
    {
      com = (STAN_COMMENT*)c->k->comment->p[i];
      fprintf (f, "C:%p:%s\n", (void*)com->addr, com->comment);
    }
  if (patch)
    {
      // Dump Patches
      n = c->k->n_patch;
      printf ("+ Dumping %d patches\n", n);
      for (i = 0; i < n; i++)
	{
	  fprintf (f, "P:%p:%d:", (void*)c->k->patch[i].off, c->k->patch[i].len);
	  for (j = 0; j < c->k->patch[i].len; j++) fprintf (f,"%02x", c->k->patch[i].data[j]);
	  fprintf (f, "\n");
	}
 
    }
  fclose (f);
  printf ("+ Case successfully save '%s'\n", fname1);
  return 0;
}

STAN_CASE *
stan_case_load (STAN_CASE *c, char *fname)
{
  FILE *f;
  char buffer[1024];
  STAN_SYM *s;

  if ((f = fopen (fname, "rt")) == NULL)
    {
      fprintf (stderr, "- Cannot open file '%s'\n", fname);
      return NULL;
    }
  while (!feof (f))
    {
      if (!fgets (buffer, 1024, f)) break;
      if (buffer[strlen(buffer) - 1] == '\n') 
	buffer[strlen(buffer) - 1] = 0;
      switch (buffer[0])
	{
	case 'S':
	  {
	    char *name, *saddr;
	    long addr;
	    name = strtok (buffer + 2, ":");
	    saddr = strtok (NULL, ":");
	    printf ("-> SYMBOL: '%s' '%s'\n", name, saddr + 2);
	    addr =strtol (saddr + 2, NULL, 16);
	    if ((s = (STAN_SYM*) stan_table_find (c->k->sym, addr)))
	      {
		if (s->id) free (s->id);
		s->id = strdup (name);
	      }
	    else
	      {
		s = stan_sym_new (name, addr);
		stan_table_add (c->k->sym, (STAN_ITEM*)s);
	      }
	    break;
	  }
	case 'L':
	  {
	    char *name, *saddr;
	    long  addr;

	    name = strtok (buffer + 2, ":");
	    saddr = strtok (NULL, ":");

	    addr =strtol (saddr + 2, NULL, 16);
	    printf ("-> LABEL: '%s' '%p'\n", name, (void*)addr);
	    if ((stan_core_rename_label_at (c->k, addr, name)) < 0)
	      {
		stan_core_def_label (c->k, name, addr);
		printf ("- Label is NEW!\n");
	      }
	    break;

	  }

	case 'F':
	  {
	    char *name, *saddr;
	    long addr;
	    name = strtok (buffer + 2, ":");
	    saddr = strtok (NULL, ":");
	    addr =strtol (saddr + 2, NULL, 16);

	    if (stan_core_rename_func_at (c->k, addr, name) < 0)
	      stan_core_def_func (c->k, name, addr);
	    printf ("-> FUNCTION: '%s' '%p'\n", name, (void*)addr);
	    break;

	  }
	case 'D':   // Function data
	  {
	    char *name, *saddr;
	    long addr;
	    name = strtok (buffer + 2, ":");
	    saddr = strtok (NULL, ":");
	    addr =strtol (saddr + 2, NULL, 16);
	    if ((s = (STAN_SYM*) stan_table_find (c->k->sym, addr)))
	      {
	        //s->type |= STAN_SYM_TYPE_FUNC;
		if (s->p) break; // If the function is already created skip
		// Otherwise initialise it to allow variable renaming
		stan_dis_func (c->k, name);
	      }
	    else
	      {
		fprintf (stderr, "- ERROR. Symbol '%s' does not exti\n", name);
	      }
	    break;

	  }
	case 'V':
	  {
	    char *fname, *name, *id;
	    long addr;

	    fname = strtok (buffer + 2, ":");
	    id= strtok (NULL, ":");
	    name = strtok (NULL, ":");

	    stan_core_func_add_var (c->k, fname, id, name);
	    break;

	  }
 
	case 'C':
	  {
	    char *comment, *saddr;
	    long addr;

	    saddr = strtok (buffer + 2, ":");
	    comment = strtok (NULL, ":");

	    addr = strtol (saddr + 2, NULL, 16);
	    printf ("-> COMMENT: '%s' '%p'\n", comment, (void*) addr);
	    stan_core_add_comment (c->k, addr, comment);
	    break;

	  }

	case 'P':
	  {
	    char *hexstr, *soff, *slen;
	    long off, len;

	    soff = strtok (buffer + 2, ":");
	    slen = strtok (NULL, ":");
	    hexstr = strtok (NULL, ":");
	    off = strtol (soff + 2, NULL, 16);
	    len = atoi (slen);

	    printf ("-> PATCH: %lx %ld '%s'\n", off, len, hexstr);
	    stan_dis_poke_offset (c->k, off, hexstr);
	    break;

	  }


	default:
	  printf ("invalid field '%s'\n", buffer);
	  continue;
	}
      
    }
  fclose (f);
  return NULL;
}


