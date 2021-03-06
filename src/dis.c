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
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>

#include <ctype.h>

#include <capstone/capstone.h>

#include "core.h"
#include "ana.h"
#include "dis.h" 
#include "func.h"

#define COM_COL 45
#define COM_COL1 COM_COL + 1
//https://en.wikipedia.org/wiki/Box-drawing_character#Unicode
#define COM_SEP  "\u2502"
#define HLINE "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524"


/* Mnemonic color table */
char *mnemonic_color[] = {
  RESET,       // STAN_IMETA_NORMAL,
  FG_GREEN,    //STAN_IMETA_CALL
  FG_LRED,     //STAN_IMETA_JMP
  FG_RED,      //STAN_IMETA_RET
  FG_LYELLOW,  //STAN_IMETA_PUSH
  FG_YELLOW,   //STAN_IMETA_POP
  FG_CYAN,     //STAN_IMETA_MOV
  FG_MAGENTA,  //STAN_IMETA_CMP
  BG_MAGENTA,  // STAN_IMETA_SYSCALL
  NULL
};

STAN_FUNC *_f;

/* Local functions */
/****************************************************/

static int
_stan_dis_op (STAN_CORE *k, STAN_SEGMENT *s, int i)
{
  int        j;
  cs_insn    *ins;
  long       eip; 
  cs_detail  *detail;
  int        n_ops = 0;
  char       *aux;
  int        nl = 0;

  ins = &k->ins[i];
  eip = ins->address; // Current IP
  
  detail = ins->detail;
  if (!detail ) return 0; // Nothing to do

  if (k->arch == STAN_CORE_ARCH_X86) n_ops = detail->x86.op_count;
  else if (k->arch == STAN_CORE_ARCH_ARM) n_ops = detail->arm.op_count;

  /* Process Operands */
  for (j = 0; j < n_ops; j++)
    {

      if (k->arch == STAN_CORE_ARCH_X86 && detail->x86.operands[j].type == X86_OP_MEM)
	{
	  if (detail->x86.operands[j].mem.base == X86_REG_RIP)
	    {
	      nl = 1;
	      aux = stan_dis_check_ptr (k, eip + 
					detail->x86.operands[j].mem.disp + 
					ins->size);
	      if (aux) 
		{
		  printf ("; %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}
	      else
		printf (FG_GREEN "; ! %p " RESET, 
			(void*)(eip + detail->x86.operands[j].mem.disp + ins->size)); 
	    }
	  else if (detail->x86.operands[j].mem.base == X86_REG_EBP ||
		   detail->x86.operands[j].mem.base == X86_REG_ESP ||
		   detail->x86.operands[j].mem.base == X86_REG_RBP
		   )
	    {
	      int a = 4;
	      int b = detail->x86.operands[j].mem.disp;
	      char id[1024];
	      snprintf (id, 1024, "ls_%s%+d", cs_reg_name (k->handle, detail->x86.operands[j].mem.base), b);
	      nl = 1;
	      STAN_LSYM *s = stan_func_get_lsym (_f, id);
	      if (!s)
		stan_func_add_lsym (_f, id, id);
	      else
		strcpy (id, s->name);

	      printf ("; "BG_RED "{%s}"RESET, id);
#if 0
	      if (detail->x86.operands[j].mem.disp < 0)
		{
		  if (b)
		    printf ("; "BG_RED "{var_%ld.%d}"RESET,
			    (-detail->x86.operands[j].mem.disp)/a, -b); 
		  else
		    printf ("; "BG_RED "{var_%ld}"RESET,
			    (-detail->x86.operands[j].mem.disp)/a); 
		}
	      else
		{
		  if (b)
		    printf ("; "BG_RED "{par_%ld.%d}"RESET,
			    (detail->x86.operands[j].mem.disp)/a - 1, b); 
		  else
		    printf ("; "BG_RED "{par_%ld}"RESET,
			    (detail->x86.operands[j].mem.disp)/a - 1); 
		}
#endif
	    }
	  else 
	    {

	      aux = stan_dis_check_ptr (k, detail->x86.operands[j].mem.disp);
	      if (aux) 
		{
		  printf ("; %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		  nl = 1;
		}
	      // Keep this for debugging untill or addressings are addressed :)
	      /*
	    printf ("; SEGMENT: %s BASE: %s Index:%s Scale:%d Disp:%d", 
		    detail->x86.operands[j].mem.segment ==  X86_REG_INVALID ? "N/A" :
		    cs_reg_name (k->handle, detail->x86.operands[j].mem.segment),
		    detail->x86.operands[j].mem.base ==  X86_REG_INVALID ? "N/A" :
		    cs_reg_name (k->handle, detail->x86.operands[j].mem.base),
		    detail->x86.operands[j].mem.index ==  X86_REG_INVALID ? "N/A" :
		    cs_reg_name (k->handle,detail->x86.operands[j].mem.index),
		    detail->x86.operands[j].mem.scale,
		    detail->x86.operands[j].mem.disp
		    );
	      */
	      
	    }

	}


      if (k->arch == STAN_CORE_ARCH_ARM && detail->arm.operands[j].type == ARM_OP_MEM)
	{
	  if (detail->arm.operands[j].mem.base == ARM_REG_PC)
	    {
	      size_t indx = i + detail->arm.operands[j].mem.disp / 4 + 2;
	      // FIXME: We should get thes from k->code
	      //        Could it be that it is not decoded by casptone?? CHECK IT
	      int ptr = 
		k->ins[indx].bytes[3] << 24 |
		k->ins[indx].bytes[2] << 16 |
		k->ins[indx].bytes[1] << 8 |
		k->ins[indx].bytes[0];
	      aux = stan_dis_check_ptr (k, ptr);
	      nl = 1;
	      if (aux) 
		{
		  printf ("; [%p] %s " RESET, 
			  (void*)(eip + detail->arm.operands[j].mem.disp +  ins->size + 4), 
			  aux);
		  free (aux);
		  aux = NULL;
		}
	      else
		printf (FG_GREEN "; !%p " RESET, 
			(void*)(eip + detail->arm.operands[j].mem.disp+ ins->size + 4));
	      
	      
	    }
	}


      if (k->arch == STAN_CORE_ARCH_X86 && detail->x86.operands[j].type == X86_OP_IMM)
	{
	  
	  if ((detail->x86.operands[j].imm < 255) && 
	      isprint ((int)(detail->x86.operands[j].imm & 0xff)))
	    printf ("; "BG_LBLUE"'%c'" RESET, (unsigned char)detail->x86.operands[j].imm);
	  else
	  
	    {
	      aux =stan_dis_check_ptr (k, detail->x86.operands[j].imm);
	      if (aux) 
		{
		  printf ("; %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		  nl = 1;
		}
	    }
	}
      else if (k->arch == STAN_CORE_ARCH_ARM && 
	       detail->arm.operands[j].type == ARM_OP_IMM)
	{
	  nl = 1;
	  if ((detail->arm.operands[j].imm < 255) && 
	      isprint ((int)(detail->arm.operands[j].imm & 0xff)))
	    printf ("; "BG_LBLUE"'%c'" RESET, (unsigned char)detail->arm.operands[j].imm);
	  else
	    {
	      aux =stan_dis_check_ptr (k, detail->arm.operands[j].imm);
	      if (aux) 
		{
		  printf ("; %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}
	      else nl = 0;
	    }
	}

    }
  
  
  return nl;
}


static int
_stan_dis_inst (STAN_CORE *k, STAN_SEGMENT *s, int i)
{
  int  j, spc;
  cs_insn *ins;
  STAN_IMETA *im;
  STAN_COMMENT *com;
  STAN_SYM   *l;

  spc = 0;
  ins = &k->ins[i];
  im = &(k->imeta[i]);
  /* Processing single instruction */
  /* Check address */
  if (im->addr || im->func)    printf("%s\n", HLINE);

  if ((l = (STAN_SYM*) stan_table_find (k->label, ins->address)) != NULL)
    {
      stan_printf (BG_RED2, "%38s:", l->id);
      printf("%*s\n", COM_COL1, COM_SEP);
    }
  if (im->addr)
    {
      if (!strcmp (im->addr->id, "__entry_point"))
	stan_printf (BG_MAGENTA, "%38s:", im->addr->id);
      else if (!strcmp (im->addr->id, "_start"))
	stan_printf (BG_MAGENTA, "%38s:", im->addr->id);
      else
	stan_printf (BG_GREEN2, "%38s:", im->addr->id);
      printf("%*s\n", COM_COL1, COM_SEP);
    }
  else if ((l = (STAN_SYM*)stan_table_find (k->func, ins->address)) != NULL)
    {
      stan_printf (BG_GREEN2, "%38s:\n", l->id);
      printf("%*s\n", COM_COL1, COM_SEP);
    }

 
  printf("%08x:   ", ins->address); 
  for (j = 0; j < 8; j++) 
    if (j < ins->size) printf ("%02x ", ins->bytes[j]); 
    else printf ("   ");

  stan_printf (mnemonic_color[im->type], "\t%s", ins->mnemonic);
  int ml = strlen (ins->mnemonic);
  ml = (ml > 8 ? 16 : 8);

  if (im->type == STAN_IMETA_JMP && im->tlabel)
    {
      spc = COM_COL - strlen (im->tlabel->id) - 2 - ml;
      stan_printf (BG_RED2, "\t<%s>", im->tlabel->id);
    }
  else if (im->type == STAN_IMETA_CALL && im->tfunc)
    {
      spc = COM_COL - strlen (im->tfunc->id) - 2 - ml;
      stan_printf (BG_GREEN2, "\t<%s>", im->tfunc->id);
    }
  else
    {
      spc = COM_COL - strlen (ins->op_str) - ml;
      stan_printf(mnemonic_color[im->type], "\t%s", ins->op_str);
    }
  
  printf("%*s", spc, COM_SEP);

  // Resolve addresses
  int nl =_stan_dis_op (k, s, i);

  if ((com = (STAN_COMMENT*) stan_table_find (k->comment, ins->address)) != NULL)
    {
      if (com->comment) 
	{
	  if (nl) stan_printf (FG_LWHITE, "\n%41s %s" RESET, ";", com->comment);
	  else stan_printf (FG_LWHITE, "%s %s" RESET, ";", com->comment);
	}
    }
  printf (" \n");

  return 0;
}

/****************************************************/

int
stan_dis (STAN_CORE *k)
{
  if (!k) return 0;

  return 0;
}


int
stan_dis_func (STAN_CORE *k, char *sname)
{
  STAN_SEGMENT *s;
  cs_insn      *insn;
  size_t       count;
  int          j;
  STAN_SYM     *f;
  STAN_SYM     *_s;
  STAN_SYM     *_s1;

  if (!k) return -1;
  if (!sname) return -1;

  _s = NULL;
  /* Find function by name*/
  if ((f = (STAN_SYM*) stan_table_find_by_name (k->func, sname)) == NULL)
    {
      if ((f = (STAN_SYM*) stan_table_find_by_name (k->sym, sname)) == NULL)
	{
	  fprintf (stderr, "- Cannot find function '%s'\n", sname);
	  return -1;
	}
    }
  if ((_s = (STAN_SYM*) stan_table_find_by_name (k->sym, sname)) == NULL)
    {
      fprintf (stderr, "- This function does not have an associated symbol!!!\n");
    }
  if ((s = stan_core_find_func_section (k, f->addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find function '%s' section. Dynamic symbol?\n", sname);
      return -1;
    }
  printf ("+ Function '%s'@%p found at section '%s'(%ld bytes)\n", 
	  sname, (void*)f->addr, s->id, s->size);
  if (!(s->type & STAN_SEGMENT_CODE)) 
    {
      fprintf (stderr, "- Section '%s' is not executable\n", sname);
      return -1;
    }
  // Analyse and Disassemble function...
  stan_ana_init_dis (k);
  // Disassemble and produce metadata
  // XXX: We are calculating the segment to get the address and we do it
  //      again inside the ANA module... 
  // TODO: Write a proper function to avoid double work

  if (_s)  // If we have an associated symbol
    {

      _f = stan_func_new (_s);
      // Create function object
      // Initialise some info
      
    }



  printf ("+ Disassembling function %s@%p\n", sname, (void*) f->addr);
  long addr1;
  addr1 = stan_ana_process_addr (k, f->addr, _f->count);
  if (addr1 != f->addr) f->addr = addr1;
  // ----
  // Now the core contains the disassembly and metadata for the
  // indicated address (the function)
  count = k->count;
  insn = k->ins;
  if (count <= 1)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }
  if (insn == NULL)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }

  int cnt = 0;

  for (j = 0; j < count; j++)
    {

      if (k->ins[j].address < f->addr) continue;
      _stan_dis_inst (k, s, j);

      if (cnt + 1 > k->count) 
	{
	  printf ("[%d] %d,%ld\n", j, cnt + 1, k->count);
	  break;
	}

      if ((_s1 = (STAN_SYM*)stan_table_find (k->sym, k->ins[j + 1].address)) != NULL) 
	{
	  if ((_s1->type == STAN_SYM_TYPE_FUNC) |
	      (_s1->type == STAN_SYM_TYPE_SECTION))
	    {
	      printf ("+ Stopped after finding symbol '%s' (%d instructions)\n", 
		      _s1->id, cnt);
	      break;
	    }
	}
      if ((_s1 = (STAN_SYM*)stan_table_find (k->func, k->ins[j + 1].address)) != NULL) 
	{
	      printf ("+ Stopped after finding symbol '%s' (%d instructions)\n", 
		      _s1->id, cnt);
	      break;

	}

      cnt++;
    }
  if (_s)
    {
      _f->count = cnt;
      stan_func_set_end (_f, k->ins[j].address);
      stan_func_set_state (_f, STAN_FUNC_INIT);
    }
  stan_ana_close_dis (k);
  _f = NULL;
  return 0;
}




int
stan_dis_section (STAN_CORE *k, char *sname)
{
  STAN_SEGMENT *s = NULL;
  cs_insn      *insn;
  size_t       count;
  int          i, j, l1;

  if (!k) return -1;
  if (!sname) return -1;

  /* Find section by name*/
  l1 = strlen (sname);
  for (i = 0; i < k->sec->n; i++)
    {
      s = (STAN_SEGMENT*) k->sec->p[i];
      if (!strncasecmp (s->id, sname, l1)) break;
    }
  if (i == k->sec->n)
    {
      fprintf (stderr, "- Section '%s' not found\n", sname);
      return -1;
    }
  if (!s) return -1;
  if (!(s->type & STAN_SEGMENT_CODE)) 
    {
      fprintf (stderr, "- Section '%s' is not executable\n", sname);
      return -1;
    }
  stan_ana_init_dis (k);
  stan_ana_process_section (k, s);
  count = k->count;
  insn = k->ins;
  if (count <= 0)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }
  if (insn == NULL)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }

  for (j = 0; j < count; j++)
    {
      _stan_dis_inst (k, s, j);
    }

  return 0;
}


 
int
stan_dis_addr (STAN_CORE *k, long addr, size_t count)
{
  STAN_SEGMENT *s;
  cs_insn      *insn;
  size_t       count1;
  int          j;


  if (!k) return -1;

  /* Find function by name*/
  if ((s = stan_core_find_func_section (k, addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find function address. \n");
      return -1;
    }
  printf ("+ Address %p found at section '%s'(%ld bytes)\n", 
	  (void*)addr, s->id, s->size);
  if (!(s->type & STAN_SEGMENT_CODE)) 
    {
      fprintf (stderr, "- Section '%s' is not executable\n", s->id);
      return -1;
    }
  // Analyse and Disassemble function...
  stan_ana_init_dis (k);
  // Disassemble and produce metadata
  // XXX: We are calculating the segment to get the address and we do it
  //      again inside the ANA module... 
  // TODO: Write a proper function to avoid double work
  printf ("+ Disassembling function @%p\n", (void*) addr);
  stan_ana_process_addr (k, addr, count);
  // ----
  // Now the core contains the disassembly and metadata for the
  // indicated address (the function)
  count1 = k->count;

  if (count1 < 0) count1 = k->count;
  else
    {
      if (count > k->count) count1 = k->count;
      else count1 = count;
    }

  insn = k->ins;
  if (count <= 1)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }
  if (insn == NULL)
    {
      fprintf (stderr, "- Section does not contain code\n");
      return -1;
    }

  int cnt = 0;
  printf ("+ Dumping %ld instructions\n", count1);
  for (j = 0; j < count1; j++)
    {
      _stan_dis_inst (k, s, j);

      cnt++;
    }

  stan_ana_close_dis (k);

  return 0;
}

 

char *
stan_dis_dump_mem (STAN_CORE *k, long addr)
{
  char buffer[1024]; // Only dump 1024
  unsigned char *c = (unsigned char *)addr;
  int  i, j;

  memset (buffer, 0, 1024);
  if (addr == 0) return NULL;
  // Check if the first characters are printable
  if ((isspace(c[0]) || isprint (c[0])) && 
      (isspace(c[1]) || isprint (c[1])) && 
      (isprint (c[2]) || c[2]==0 || isspace(c[2])))
    {
      j =0;
      buffer[j++] = '\'';
      // Copy buffer removing 
      for (i = 0; i < 1024 && j < 1023 && c[i]; i++)
	{
	  if (c[i] == '\n') 
	    {
	      buffer[j++] = '\\';
	      buffer[j++] = 'n';
	      continue;
	    }

	  if (c[i] < 0x20) continue;
	  buffer[j++] = c[i];
	  if (c[i] == 0) break;
	}
      buffer[j++] = '\'';
    }
  else // Binary data
    {
      char *p = buffer;
      STAN_SYM *s;
      if ((s = (STAN_SYM*) stan_table_find (k->sym, *(long*)addr)) != NULL)
	p += sprintf (p, "[<%s> %p]", s->id, (void*)(*(long*)addr));
    }
    
  return strdup (buffer);
}


// Returns a description of the pointer addr
char*
stan_dis_check_ptr (STAN_CORE *k, long ptr)
{
  long         i, rel, _n_sec;
  char         buffer[1024];
  STAN_SYM     *s;
  STAN_SEGMENT *sec;

  memset (buffer, 0, 1024);
  if (ptr == 0) return NULL;
  s = (STAN_SYM*) stan_table_find (k->sym, ptr);

  _n_sec = k->sec->n;
  for (i = 0; i < _n_sec; i++)
    {
      sec = (STAN_SEGMENT*) k->sec->p[i];
      rel = ptr - sec->addr;
      // Check if value is in section and try to print data
      if (rel >= 0 && (rel < sec->size))
	{
	  char *str;
	  
	  if (!(sec->type & STAN_SEGMENT_CODE)) // Section is data... treat as a function
	    {
	      str = stan_dis_dump_mem (k, (long)(k->code + sec->off + rel));
	      if (!s)
		  snprintf (buffer, 1024, 
			    FG_BLUE "%lx(%s+%lx) " RESET " : " BG_RED "%s" RESET,
			    ptr, sec->id, rel, str);
	      else
		  snprintf (buffer, 1024, 
			    FG_BLUE "<%s> %lx(%s+%lx) " RESET " : " BG_RED "%s" RESET,
			    s->id, ptr, sec->id, rel, str);

	      
	      free (str);
	    }
	  else // Otherwise it is code...
	    {
	      char *aux = buffer;
	      str = stan_dis_dump_mem (k, (long)(k->code + sec->off + rel));
	      if (s == NULL) /// If we do not have a symbol show the pointer 
		{
		  aux += snprintf (buffer, 1024, FG_GREEN "%lx(%s+0x%lx)" RESET,
				   ptr, sec->id, rel);
		  if (str[0] != '0')
		    aux += snprintf (aux, 1024, FG_GREEN " %s " RESET, str);

		}
	      else // Otherwise also dump the symbol
		{
		  aux += snprintf (buffer, 1024, FG_GREEN "<%s> %lx(%s+0x%lx)" RESET,
				   s->id, ptr, sec->id, rel);
		}
	      free (str);
	    }
	  
	  return strdup (buffer);
	}
      
      
    }
  // If the pointer does not belong to a segment... consider it data
  if (i == _n_sec)
    {
      unsigned char *p = (unsigned char*) &ptr;

      if (isprint (p[0]) && isprint (p[1]) && isprint(p[2]) && isprint(p[3]))
	{
	  snprintf (buffer, 1024, FG_BLUE "'%c%c%c%c'" RESET, p[0], p[1], p[2], p[3]);
	  return strdup(buffer);
	}
    }
  if (s) 
    {
      
      snprintf (buffer, 1024, FG_GREEN " %p <%s>  " RESET, 
		(void*)s->addr, s->id);
      return strdup(buffer);
    }
  
  return NULL;
  
}


/* ********************************************************
 * **  TODO: Move all this to a memory manipulation module
 */

#define DUMP_SIZE 16
#define DUMP_WSIZE 8

static int
_dump_bytes (long base, long addr, long len)
{
  int  i;
  char *ascii;

  ascii = malloc (DUMP_SIZE + 1);
  memset (ascii, 0, DUMP_SIZE + 1);
  unsigned char *p = (unsigned char*)addr;

  printf ("          | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f |0123456789abcdef\n");
  printf ("----------+-------------------------------------------------+----------------\n");

  printf ("%p : ", (void*) (base));
  for (i = 0; i < len; i++)
    {
      if ((i > 0) & ((i % DUMP_SIZE) == 0)) 
	{

	  printf ("|%s\n%p : ", ascii, (void*)(base + i));
	  memset (ascii, 0, DUMP_SIZE);
	}
      printf ("%02x ", p[i]);
      ascii[i % DUMP_SIZE] = ((isprint (p[i]) && (p[i] >= 0x20)) ? p[i] : '.');

    }
  printf ("%*c", (DUMP_SIZE - (i % DUMP_SIZE)) * 3,' ');
  if ((i % DUMP_SIZE) != 0) printf ("|%s\n", ascii);
  else printf ("\n");

  free (ascii);
  return 0;

}

static int
_dump_addresses (STAN_CORE *k, long base, long addr, long len)
{
  int      i;
  STAN_SYM *s;
  int      rel;
  long *p = (long *)addr;
  int *p1 = (int *)addr;

  // Find closest symbol
  for (i = 0; i < len; i++)
    {
      // Resolve symbols!!
      s = stan_core_get_closest_symbol (k, p[i]);
      if (k->mode == STAN_CORE_MODE_64)
	printf ("%p: %p\t", (void*) base + i*sizeof(long), (void*) p[i]);
      else
	printf ("%p: %p\t", (void*) base + i*sizeof(long), (void*) p1[i]);
      if (s)
	{
	  rel = p[i] - s->addr;
	  if (rel >= 0 && rel < 0x1000) // XXX: We have to actually checka against segment
	    {
	      if (k->mode == STAN_CORE_MODE_64)
		printf ("<%s %+ld>", s->id, p[i] - s->addr);
	      else
		printf ("<%s %+d>", s->id, p1[i] - (int)s->addr);
	    }
	  
	}
      printf ("\n");
    }
  printf ("\n");
  return 0;
}


int
stan_dis_dump_block (STAN_CORE *k, char *fmt, long addr, long len)
{
  STAN_SEGMENT   *s;
  long           ptr;

  if (!k) return -1;
  if (!fmt) return -1;
  if (!addr) return -1;
  if (len < 0) return -1;

  // Find segment for the provided address
  if ((s = stan_core_find_func_section (k, addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find code for address %p\n", (void*)addr);
      return -1;
    }
  // Calculate real address
  printf ("+ Dumping %ld items from segment '%s'\n", len, s->id);
  ptr = (long)(k->code + s->off + (addr - s->addr));
  if (!strcmp (fmt, "x")) _dump_bytes (addr, ptr, len);
  else if (!strcmp (fmt, "p")) _dump_addresses (k, addr, ptr, len);

  return 0;
}

int
stan_dis_poke_bytes (STAN_CORE *k, long addr, char *str)
{
  int  i, l = strlen (str);
  char v, *p = str;
  unsigned char *data;
  l >>= 1; 
  data = malloc (l);

  v= 0;
  printf ("Writting %d bytes\n", l);
  for (i = 0; i < l; i++)
    {
      printf ("Byte %d\n", i);
      sscanf (p, "%02x", (unsigned int *) &v);
      data[i] = v;
      printf ("Wrote %02x to %p\n", (unsigned char)v, (void*)((unsigned char*)addr + i));
      *(unsigned char*)((unsigned char*)addr + i) = (unsigned char) v;

      p+=2;
    }
  stan_core_add_patch (k, addr - (long)k->code, l, data);
  return 0;
}


int
stan_dis_poke_offset (STAN_CORE *k, long off, char *str)
{
  int  i, l = strlen (str);
  char v, *p = str;
  long addr = (long) k->code + off;
  unsigned char *data;

  l >>= 1; 
  data = malloc (l);

  v= 0;
  printf ("Writting %d bytes\n", l);
  for (i = 0; i < l; i++)
    {
      printf ("Byte %d\n", i);
      sscanf (p, "%02x", (unsigned int *) &v);
      data[i] = v;
      printf ("Wrote %02x to %p\n", (unsigned char)v, (void*)((unsigned char*)addr + i));
      *(unsigned char*)((unsigned char*)addr + i) = (unsigned char) v;

      p+=2;
    }
  stan_core_add_patch (k, off, l, data);
  return 0;
}


int
stan_dis_poke_block (STAN_CORE *k, char *fmt, long addr, char*str)
{
  STAN_SEGMENT   *s;
  long           ptr;

  if (!k) return -1;
  if (!fmt) return -1;
  if (!addr) return -1;
  if (!str) return -1;

  // Find segment for the provided address
  if ((s = stan_core_find_func_section (k, addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find code for address %p\n", (void*)addr);
      return -1;
    }
  // Calculate real address

  ptr = (long)(k->code + s->off + (addr - s->addr));
  if (!strcmp (fmt, "x")) stan_dis_poke_bytes (k, ptr, str);
  else if (!strcmp (fmt, "s")) memcpy ((void*)ptr, (void*)str, strlen(str));
  else if (!strcmp (fmt, "p")) *((int *)ptr) = atoi (str);

  return 0;
}

int
stan_dis_generate_labels (STAN_CORE *k, char *prefix, long addr, long len)
{
  int      i, cnt;
  STAN_SEGMENT   *s;
  STAN_SYM *s1;
  char     buffer[1024];
  long           ptr;
  long *p;
  int *p1;

  // Find closest symbol
  if ((s = stan_core_find_func_section (k, addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find code for address %p\n", (void*)addr);
      return -1;
    }
  // Calculate real address
  ptr = (long)(k->code + s->off + (addr - s->addr));
  p = (long *)ptr; 
  p1 = (int *)ptr;

  cnt = 0;
  for (i = 0; i < len; i++)
    {
      // Resolve symbols!!
      if (k->mode == STAN_CORE_MODE_64)
	s1 = (STAN_SYM*) stan_table_find (k->label, p[i]);
      else
	s1 = (STAN_SYM*) stan_table_find (k->label, p1[i]);
      if (s1) continue;  /// We skip this if we already have a symbol
      // Otherwise we create a label
      snprintf (buffer, 1024, "%s_%d", prefix, i);
      if (k->mode == STAN_CORE_MODE_64)
	{
	  s1 = stan_core_add_label (k, p[i]);
	}
      else
	{
	  s1 = stan_core_add_label (k, p1[i]);
	}
      if (s1->id) free (s1->id);
      s1->id = strdup (buffer);
      s1->dump = 1;
      cnt++;
    }
  printf ("+ %d labels generated\n", cnt);
  printf ("\n");
  return 0;
}

int
stan_mem_xor (STAN_CORE *k, char *key, long addr, long addr1)
{
  STAN_SEGMENT *s;
  long         ptr, ptr1, p;
  int           l,v, i;
  unsigned char *k1, c;

  if ((s = stan_core_find_func_section (k, addr)) == NULL)
    {
      fprintf (stderr, "- Cannot find code for address %p\n", (void*)addr);
      return -1;
    }
  ptr = (long)(k->code + s->off + (addr - s->addr));  

  if ((s = stan_core_find_func_section (k, addr1)) == NULL)
    {
      fprintf (stderr, "- Cannot find code for address %p\n", (void*)addr1);
      return -1;
    }
  ptr1 = (long)(k->code + s->off + (addr1 - s->addr));  
  printf ("Key '%s' %ld\n", key, strlen(key));
  l = strlen (key) >> 1;
  printf ("Key is %d bytes long... parsing\n", l);
  k1 = malloc (l);
  for (i = 0; i < l; i++)
    {
      sscanf (key, "%02x", &v);
      k1[i] = (unsigned char)v;
    }
  
  for (i=0, p = ptr; p < ptr1; p++, i++)
    {
      c = *((unsigned char*)p);     
      *((unsigned char*)p) = c ^ k1[i % l];
    }

}
