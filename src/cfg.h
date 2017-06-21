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
#ifndef STAN_CFG_H
#define STAN_CFG_H

typedef struct stan_cfg_pair_t
{
  char *key;
  char *val;
} STAN_CFG_PAIR;

#ifdef __cplusplus
extern "C" {
#endif

  int    stan_cfg_init ();
  void   stan_cfg_dump ();
  int    stan_cfg_set (char *key, char *value);
  char*  stan_cfg_get (char *key);

#ifdef __cplusplus
}
#endif



#endif
