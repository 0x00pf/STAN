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

/* Process ELF 32bits 
 * ----------------------------------
 */
#ifndef STAN_ELF32_H
#define STAN_ELF32_H

#include "core.h"

#ifdef __cplusplus
extern "C" {
#endif

  int  stan_elf32_init (STAN_CORE *k);
  int  stan_elf32_process (STAN_CORE *k);

#ifdef __cplusplus
}
#endif

#endif
