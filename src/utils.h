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

// fstat

#ifndef STAN_UTIL_H
#define STAN_UTIL_H


#define FG_LYELLOW "\033[1;33m"
#define FG_YELLOW "\033[0;33m"
#define FG_GREEN "\033[1;32m"
#define FG_LGREEN "\033[0;32m"
#define FG_BLUE "\033[1;34m"
#define BG_LBLUE "\033[1;44m"
#define BG_BLUE "\033[0;44m"
#define BG_CYAN "\033[1;30;1;46m"
#define BG_MAGENTA "\033[1;37;1;45m"

#define FG_CYAN "\033[1;36m"
#define FG_MAGENTA "\033[1;35m"
#define FG_LBLUE "\033[0;34m"
#define FG_LWHITE "\033[1;37m"

#define BG_LMAGENTA "\033[37;1;45;0m"
#define BG_RED2 "\033[0;37;1;41m"
#define BG_GREEN2 "\033[0;37;1;42m"
//#define BG_GREEN "\033[1;37m\033[0;42m"
#define FG_RED "\033[0;31m"
#define FG_LRED "\033[1;31m"
//#define BG_RED "\033[0;41m"
#define BG_RED "\033[0;44;1;33m"

#define RESET "\033[0m"



// Macros
#define STAN_CHECK_RANGE(v,min,max) (v >= min && v <= max)

/* Base type for STAN Tables */
typedef struct stan_item_t
{
  long  addr;
  char  *name;
  int   dump;   // Indicated id the item has to be dumped
} STAN_ITEM;

typedef int (*STAN_ITEM_FREE)(STAN_ITEM*);

/* Generic STAN Table */
typedef struct stan_table_t
{
  int            n;
  int            esize;
  STAN_ITEM_FREE f;
  STAN_ITEM      **p;
} STAN_TABLE;


#ifdef __cplusplus
extern "C" { 
#endif
  
  /* Generic Table interface */
  /*
  STAN_TABLE* stan_table_new (int esize);
  int         stan_table_free (STAN_TABLE* t, STAN_ITEM_FREE f);
  */
  STAN_TABLE* stan_table_new (STAN_ITEM_FREE f, int esize);
  int         stan_table_free (STAN_TABLE* t);

  int         stan_table_sort (STAN_TABLE* t);
  
  int        stan_table_add  (STAN_TABLE* t, STAN_ITEM *e);
  int        stan_table_add_dups  (STAN_TABLE* t, STAN_ITEM *e);
  STAN_ITEM* stan_table_find (STAN_TABLE* t, long addr);
  STAN_ITEM* stan_table_find_by_name (STAN_TABLE* t, char *name);
  int        stan_table_get_index (STAN_TABLE* t, long addr);
  int        stan_table_get_index_by_name (STAN_TABLE* t, char *name);


  int stan_util_get_file_size (int fd);
  int stan_printf (char *color, char* fmt, ...);

#ifdef __cplusplus
}
#endif


#endif
