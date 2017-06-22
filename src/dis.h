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

/* Code Analiser.... common code
 * ----------------------------------
 */
#ifndef STAN_DIS_H
#define STAN_DIS_H

#include "core.h"


#ifdef __cplusplus
extern "C" {
#endif

  int    stan_dis (STAN_CORE *k);
  int    stan_dis_section (STAN_CORE *k, char *sname);
  int    stan_dis_addr (STAN_CORE *k, long addr, int count);
  int    stan_dis_func (STAN_CORE *k, char *fname);

  char*  stan_dis_check_ptr (STAN_CORE *k, long addr);
  char*  stan_dis_dump_mem (STAN_CORE *k, long addr);
  int    stan_dis_dump_block (STAN_CORE *k, char *fmt, long addr, long len);
  int    stan_dis_poke_block (STAN_CORE *k, char *fmt, long addr, char*str);
#ifdef __cplusplus
}
#endif

#endif
