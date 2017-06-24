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
#ifndef STAN_ANA_H
#define STAN_ANA_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

  int  stan_ana_init (STAN_CORE *k);
  int  stan_ana_init_dis (STAN_CORE *k);
  int  stan_ana_close_dis (STAN_CORE *k);

  //int stan_ana_process_current_code (STAN_CORE *k);

  long stan_ana_process_addr (STAN_CORE *k, long addr);
  long stan_ana_process_section ( STAN_CORE *k, STAN_SEGMENT *s);

#ifdef __cplusplus
}
#endif

#endif
