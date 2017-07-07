dnl  STAN STAN is a sTAtic aNalyser
dnl  Copyright (c) 2017 pico
dnl 
dnl  This program is free software: you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation, either version 3 of the License, or
dnl  (at your option) any later version.
dnl 
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl 
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl 

AC_INIT([stan], 0.6.1, [@0x00pf])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_SRCDIR([src/stan.c])
AC_CONFIG_MACRO_DIR([m4])

AM_PROG_AR
AC_PROG_CC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

AC_CHECK_LIB(capstone, main)
AC_CHECK_LIB(readline, main)
AC_CONFIG_HEADERS([config.h])
CFLAGS+=-g -O0 -Wall

AC_CHECK_HEADER(elf.h)

AC_CONFIG_FILES([Makefile \
		src/Makefile])
AC_OUTPUT
