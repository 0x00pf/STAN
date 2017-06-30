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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

// fstat
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"


STAN_TABLE* 
stan_table_new (STAN_ITEM_FREE f, int esize)
{
  STAN_TABLE *t;

  if ((t = malloc (sizeof(STAN_TABLE))) == NULL)
    {
      fprintf (stderr, "- Cannot allocate symbol table\n)");
      return NULL;
    }

  t->n = 0;
  t->f = f;
  t->p = NULL;
  t->esize = esize;

  return t;
}

int        
stan_table_free (STAN_TABLE* t)
{
  int   i;

  if (!t) return -1;

  // Release  items
  for (i = 0; i < t->n; i++) if (t->p[i]) t->f (t->p[i]);
  
  free (t);
  return 0;
}



static int
stan_item_cmpaddr (const void *p1, const void *p2)
{

  STAN_ITEM *l1 = *(STAN_ITEM **)p1;
  STAN_ITEM *l2 = *(STAN_ITEM **)p2;

  if (l1->addr < l2->addr) return -1;
  else if (l1->addr > l2->addr) return 1;
  else return 0;

}


int        
stan_table_sort (STAN_TABLE* t)
{
  qsort (&t->p[0], t->n, sizeof(STAN_ITEM*), stan_item_cmpaddr);
  return 0;
}

int        
stan_table_add_dups  (STAN_TABLE* t, STAN_ITEM *e)
{

  int i;

  if (!t) return -1;
  if (!e) return -1;

  // Check if item already exists
  i = t->n;
  
  t->n++;
  if ((t->p = realloc (t->p, t->n * sizeof(STAN_ITEM*))) == NULL)
    {
      fprintf (stderr, "- Cannot resize STAN table\n");
      return -1;
    }
  t->p[i] = e;
  return 0;

}

int
stan_table_add  (STAN_TABLE* t, STAN_ITEM* e)
{
  STAN_ITEM* s;
  int i;

  if (!t) return -1;
  if (!e) return -1;

  // Check if item already exists
  i = t->n;
  if ((s = stan_table_find (t, e->addr)) == NULL)
    {
      // Symbol not found... adding
      t->n++;
      if ((t->p = realloc (t->p, t->n * sizeof(STAN_ITEM*))) == NULL)
	{
	  fprintf (stderr, "- Cannot resize STAN table\n");
	  return -1;
	}
      t->p[i] = e;
    }
  else // The item exists... shall we update?
    {
      if (strcmp (e->name, "NONAME"))
	{
	  if (s->name) 
	    {
	      free (s->name);
	      s->name = strdup (e->name);
	    }
	  t->f (e);
	}
    }
  return 0;
}


STAN_ITEM*  
stan_table_find (STAN_TABLE* t, long addr)
{
  int i;

  if (!t) return NULL;
  for (i = 0; i < t->n; i++)
    if (t->p[i]->addr == addr) return t->p[i];
  
  return NULL;
}

STAN_ITEM* 
stan_table_find_by_name (STAN_TABLE* t, char *name)
{
  int i;

  if (!t) return NULL;
  for (i = 0; i < t->n; i++)
    {
      if (!strcmp (t->p[i]->name, name)) return t->p[i];
    }
  
  return NULL;

}

int        
stan_table_get_index (STAN_TABLE* t, long addr)
{
  int i;

  if (!t) return -1;
  for (i = 0; i < t->n; i++)
    if (t->p[i]->addr == addr) return i;
  
  return -1;

}

int        
stan_table_get_index_by_name (STAN_TABLE* t, char *name)
{
  int i;

  if (!t) return -1;
  if (!name) return -1;
  for (i = 0; i < t->n; i++)
    {
      if (!strncmp (t->p[i]->name, name, strlen(name))) return i;
    }
  
  return -1;

}


/********************************************************/
int 
stan_util_get_file_size (int fd)
{
  struct stat _info;
  
  fstat (fd, &_info);
  
  return _info.st_size;
}


#define BUF_SIZE 4096
int 
stan_printf (char *color, char* fmt, ...)
{
  char    buf[BUF_SIZE];
  int     len, flag;
  va_list arg;

  if (!color) return -1;
  if (!fmt) return -1;

  va_start (arg, fmt);

  memset (buf, 0, BUF_SIZE);
  printf ("%s", color);
  len = vsnprintf (buf, BUF_SIZE, fmt, arg);
  flag = 0;
  if (buf[len - 1] == '\n')
    {
      buf[len - 1] = 0;
      flag = 1;
    }

  printf ("%s", buf);
  printf ("%s", RESET);
  if (flag) printf ("\n");
  fflush (stdout);
  va_end (arg);

  return len;

}
