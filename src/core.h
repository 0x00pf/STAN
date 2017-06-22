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
#ifndef STAN_CORE_H
#define STAN_CORE_H


#include <capstone/capstone.h>
#include "symb.h"
#include "utils.h"


#define STAN_CORE_TYPE_UKNOWN  0
#define STAN_CORE_TYPE_ELF_64  1
#define STAN_CORE_TYPE_ELF_32  2
#define STAN_CORE_TYPE_RAW     3
#define STAN_CORE_TYPE_LAST    3



#define STAN_CORE_OS_UNKNOWN   0
#define STAN_CORE_OS_NONE      1
#define STAN_CORE_OS_LINUX     2
#define STAN_CORE_OS_LAST      2

#define STAN_CORE_ARCH_UNKNOWN 0
#define STAN_CORE_ARCH_X86     1
#define STAN_CORE_ARCH_ARM     2
#define STAN_CORE_ARCH_LAST    2

#define STAN_CORE_MODE_UNKOWN  0
#define STAN_CORE_MODE_32      1
#define STAN_CORE_MODE_64      2
#define STAN_CORE_MODE_ARM     3
#define STAN_CORE_MODE_THUMB   4
#define STAN_CORE_MODE_LAST    4

#define STAN_CORE_INVALID      0
#define STAN_CORE_VALID        1


// This represents segments from the binary
// Sections are managed as subsegments...
// In principle we will not disassemble Segments (Program Headers)
// but sections

#define STAN_SEGMENT_UNKNOWN 0
#define STAN_SEGMENT_CODE    1
#define STAN_SEGMENT_DATA    2
#define STAN_SEGMENT_WRITE   4
#define STAN_SEGMENT_SECTION 8

#define STAN_IMETA_NORMAL  0
#define STAN_IMETA_CALL    1
#define STAN_IMETA_JMP     2
#define STAN_IMETA_RET     3
#define STAN_IMETA_PUSH    4
#define STAN_IMETA_POP     5
#define STAN_IMETA_MOV     6
#define STAN_IMETA_CMP     7
#define STAN_IMETA_SYSCALL 8


/*
 *  Operartors
 *  op[0] -> Target for JMP/CALL
 *  op[1] -> 
 */

typedef struct stan_imeta_t
{
  int         type;
  STAN_SYM*   addr;   // Symbol associated to this address if any 
  STAN_SYM*   label;  // In case this addr is a label
  STAN_SYM*   func;   // In case this addr is a func
  STAN_SYM*   tlabel;  // In case it is a label (target jump)
  STAN_SYM*   tfunc;   // In case it is a func  (target call)

  char*       op[4];  // Operations resolution strings... XXX: May need changing
  char*       comment;
} STAN_IMETA;

// THis is also a STAN_ITEM object
typedef struct stan_segment_t
{
  long        addr; 
  char        *id;
  int         dump;
  int         type;
  long        off;
  long        size;
  long        esize;
  long        a0;
  long        a1;
  cs_insn     *ins;
  STAN_IMETA  *imeta; // Stores instruction metadata... array of size count
  size_t      count;
  void        *p; 
} STAN_SEGMENT;

typedef struct stan_core_t
{
  char       *fname;
  void       *code;
  long       size;
  int        valid;
  int        fd;
  int        type; // Type of core
  int        os;   // OS/ABI for the core
  int        arch; // Architecture of the core
  int        mode; // 32/64 bits
  long       ep;   // Entry Point
  int        l_cnt;
  csh        handle;
  STAN_TABLE *seg;
  STAN_TABLE *sec;
  STAN_TABLE *sym;
  STAN_TABLE *dsym;
  STAN_TABLE *func;
  STAN_TABLE *label;
  // API -> core type dependant
  int   (*core_init) (struct stan_core_t *k);
  int   (*core_process) (struct stan_core_t *k);
} STAN_CORE;  // Memory Mapped binary

#ifdef __cplusplus
extern "C" {
#endif

  int        stan_core_init (); // Init core loaders
  STAN_CORE *stan_core_new ();
  int        stan_core_free (STAN_CORE *k);
  int        stan_core_clean (STAN_CORE *k);

  int        stan_core_identify (STAN_CORE *k);
  int        stan_core_set  (STAN_CORE *k, int arch, int mode, int os);
  int        stan_core_load (STAN_CORE *k, char *fname);
  int        stan_core_save (STAN_CORE *k, char *fname);


  int         stan_core_dump (STAN_CORE *k);
  int         stan_core_dump_symbols (STAN_CORE *k);
  int           stan_core_dump_func (STAN_CORE *k);
  int           stan_core_dump_label (STAN_CORE *k);


  int           stan_core_get_cs_arch (STAN_CORE *k);
  int           stan_core_get_cs_mode (STAN_CORE *k);
  char         *stan_core_get_os_name (STAN_CORE *k);
  char         *stan_core_get_arch_name (STAN_CORE *k);
  char         *stan_core_get_mode_name (STAN_CORE *k);


  STAN_SEGMENT *stan_segment_new ();
  int           stan_segment_free (STAN_SEGMENT*);
  STAN_SEGMENT *stan_segment_clone (STAN_SEGMENT*);
  
  STAN_IMETA   *stan_imeta_new (STAN_CORE *k, STAN_SEGMENT *s);

  STAN_SYM*     stan_core_add_func (STAN_CORE *k, long addr);
  STAN_SYM*     stan_core_add_label (STAN_CORE *k, long addr);

  int           stan_core_dump_func (STAN_CORE *k);
  int           stan_core_dump_label (STAN_CORE *k);

  int           stan_core_rename_func_at (STAN_CORE *k, long addr, char *name);
  int           stan_core_rename_label_at (STAN_CORE *k, long addr, char *name);

  int           stan_core_rename_func (STAN_CORE *k, char *name, char *name1);
  int           stan_core_rename_label (STAN_CORE *k, char *name, char *name1);
  int           stan_core_def_func (STAN_CORE *k, char *name, long addr);
  int           stan_core_def_sym (STAN_CORE *k, char *name, long addr);
  STAN_SEGMENT* stan_core_find_func_section (STAN_CORE *k, long addr);
  int           stan_core_add_comment (STAN_CORE *k, long addr, char *comment);
  int           stan_core_del_comment (STAN_CORE *k, long addr);

  // Util FUnctions
  int           stan_core_ptr_segment (STAN_CORE *k, long addr);
#ifdef __cplusplus
}
#endif

#endif
