#  STAN STAN is a sTAtic aNalyser
#  Copyright (c) 2017 pico
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

bin_PROGRAMS=stan

stanincludedir  = $(includedir)/stan
staninclude_HEADERS=case.h core.h utils.h symb.h dis.h ana.h elf32.h elf64.h func.h cfg.h
EXTRA_DIST=case.h core.h utils.h symb.h dis.h ana.h elf32.h elf64.h func.h cfg.h

stan_SOURCES=stan.c
#stan_CFLAGS=${CFLAGS} -Wall -O0 -std=c99 -D_GNU_SOURCE=1
#stan_CFLAGS=${MY_CFLAGS} 
stan_LDADD=-lcapstone -lreadline libstan.la

lib_LTLIBRARIES=libstan.la
libstan_la_SOURCES=case.c core.c utils.c symb.c elf64.c elf32.c \
		   ana.c dis.c func.c cfg.c
#libstan_la_CFLAGS=${MY_CFLAGS}
#libstan_la_CFLAGS=${CFLAGS} -Wall -O0 -std=c99 -D_GNU_SOURCE=1

