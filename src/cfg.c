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

#include "cfg.h"

static STAN_CFG_PAIR **stan_cfg = NULL;
static int _n_cfg = 0;

static int
_stan_cfg_find_key (char *key)
{
  int  i = 0;
  int  l;

  if (!key) return -1;
  l = strlen (key);
  for (i = 0; stan_cfg[i]->key; i++)
    if (!strncasecmp (stan_cfg[i]->key, key, l)) return i;
  return -1;
}

static STAN_CFG_PAIR*
_stan_cfg_pair_new (char *key, char *val)
{
  STAN_CFG_PAIR *p;
  
  if (!key) return NULL;
  if (!val) return NULL;

  p = malloc (sizeof(STAN_CFG_PAIR*));
  p->key = strdup (key);
  p->val = strdup (val);
  return p;
}

static int
_stan_cfg_add_pair (STAN_CFG_PAIR *p)
{
  int  i = _n_cfg;
  STAN_CFG_PAIR **aux;

  if (!p) return -1;

  _n_cfg++;
  if ((aux = realloc (stan_cfg, sizeof(STAN_CFG_PAIR) * _n_cfg)) == NULL)
    {
      fprintf (stderr, "- Cannot allocate memory for configuration\n");
      _n_cfg--;
      return -1;
    }

  stan_cfg = aux;
  stan_cfg[i] = p;
  return 0;
}

int
stan_cfg_init ()
{

  _stan_cfg_add_pair (_stan_cfg_pair_new ("color", "1"));
  _stan_cfg_add_pair (_stan_cfg_pair_new ("syntax", "Intel"));
  
  return 0;
}

void
stan_cfg_dump ()
{
  int i;
  for (i = 0; i < _n_cfg; i++)
    printf ("%s\t\t: %s\n", stan_cfg[i]->key, stan_cfg[i]->val);
}

int  
stan_cfg_set (char *key, char *val)
{
  int i;

  if (!key) return -1;
  if (!val) return -1;

  if ((i = _stan_cfg_find_key (key)) < 0) 
    {
      fprintf (stderr, "- Key '%s' not found\n", key);
      return -1;
    }
  if (stan_cfg[i]->val) free (stan_cfg[i]->val);
  stan_cfg[i]->val = strdup (val);
  return 0;
}

char*  
stan_cfg_get (char *key)
{
  int i;

  if (!key) return NULL;
  if ((i = _stan_cfg_find_key (key)) < 0) 
    {
      fprintf (stderr, "- Key '%s' not found\n", key);
      return NULL;
    }
  return stan_cfg[i]->val;
}
