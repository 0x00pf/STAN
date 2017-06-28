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

/* Mnemonic color table */
char *mnemonic_color[] = {
  RESET,      // STAN_IMETA_NORMAL,
  FG_GREEN,   //STAN_IMETA_CALL
  FG_LRED,    //STAN_IMETA_JMP
  FG_RED,     //STAN_IMETA_RET
  FG_LYELLOW, //STAN_IMETA_PUSH
  FG_YELLOW,  //STAN_IMETA_POP
  FG_CYAN,    //STAN_IMETA_MOV
  FG_MAGENTA, //STAN_IMETA_CMP
  BG_MAGENTA,  // STAN_IMETA_SYSCALL
  NULL
};

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
	      aux = stan_dis_check_ptr (k, eip + detail->x86.operands[j].mem.disp + ins->size);
	      if (aux) 
		{
		  printf ("# %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}
	      else
		printf (FG_GREEN "# ! %p " RESET, 
			(void*)(eip + detail->x86.operands[j].mem.disp + ins->size)); 
	    }
#if 1
	  else 
	    {
	      aux = stan_dis_check_ptr (k, detail->x86.operands[j].mem.disp);
	      if (aux) 
		{
		  printf ("# %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}

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
#endif
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
	      if (aux) 
		{
		  printf ("# [%p] %s " RESET, 
			  (void*)(eip + detail->arm.operands[j].mem.disp +  ins->size + 4), aux);
		  free (aux);
		  aux = NULL;
		}
	      else
		printf (FG_GREEN "# !%p " RESET, 
			(void*)(eip + detail->arm.operands[j].mem.disp+ ins->size + 4));
	      
	      
	    }
	}


      if (k->arch == STAN_CORE_ARCH_X86 && detail->x86.operands[j].type == X86_OP_IMM)
	{
	  
	  if ((detail->x86.operands[j].imm < 255) && isprint ((int)(detail->x86.operands[j].imm & 0xff)))
	    printf ("# "BG_LBLUE"'%c'" RESET, (unsigned char)detail->x86.operands[j].imm);
	  else
	  
	    {
	      aux =stan_dis_check_ptr (k, detail->x86.operands[j].imm);
	      if (aux) 
		{
		  printf ("# %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}
	    }
	}
      else if (k->arch == STAN_CORE_ARCH_ARM && 
	       detail->arm.operands[j].type == ARM_OP_IMM)
	{
	  
	  if ((detail->arm.operands[j].imm < 255) && isprint ((int)(detail->arm.operands[j].imm & 0xff)))
	    printf ("# "BG_LBLUE"'%c'" RESET, (unsigned char)detail->arm.operands[j].imm);
	  else
	  
	    {
	      aux =stan_dis_check_ptr (k, detail->arm.operands[j].imm);
	      if (aux) 
		{
		  printf ("# %s " RESET, aux);
		  free (aux);
		  aux = NULL;
		}
	    }
	}

    }
  
  
  return 0;
}


static int
_stan_dis_inst (STAN_CORE *k, STAN_SEGMENT *s, int i)
{
  int  j;
  cs_insn *ins;
  STAN_IMETA *im;
  STAN_COMMENT *com;
  STAN_SYM   *l;

  ins = &k->ins[i];
  im = &(k->imeta[i]);
  /* Processing single instruction */
  /* Check address */
  if (im->addr || im->func)  printf ("\n");

  if ((l = (STAN_SYM*) stan_table_find (k->label, ins->address)) != NULL)
    stan_printf (BG_RED2, "%38s:\n", l->id);
  if (im->addr)
    {
      if (!strcmp (im->addr->id, "__entry_point"))
	  stan_printf (BG_MAGENTA, "%38s:\n", im->addr->id);
      else if (!strcmp (im->addr->id, "_start"))
	stan_printf (BG_MAGENTA, "%38s:\n", im->addr->id);
      else
	stan_printf (BG_GREEN2, "%38s:\n", im->addr->id);
    }
  else if ((l = (STAN_SYM*)stan_table_find (k->func, ins->address)) != NULL)
    stan_printf (BG_GREEN2, "%38s:\n", l->id);

  
  printf("%"PRIx64":   ", ins->address); 
  for (j = 0; j < 8; j++) 
    if (j < ins->size) printf ("%02x ", ins->bytes[j]); 
    else printf ("   ");

  stan_printf (mnemonic_color[im->type], "\t%s", ins->mnemonic);

  if (im->type == STAN_IMETA_JMP && im->tlabel)
    {
      stan_printf (BG_RED2, "\t<%s>\t", im->tlabel->id);
      printf ("\t\t");
    }
  else if (im->type == STAN_IMETA_CALL && im->tfunc)
    {
      stan_printf (BG_GREEN2, "\t<%s>\t", im->tfunc->id);
      printf ("\t\t");
    }
  else
    {
      stan_printf(mnemonic_color[im->type], "\t%s\t", ins->op_str);
      printf ("\t");
    }
  // Resolve addresses
  _stan_dis_op (k, s, i);

  printf (" \n");
  if ((com = (STAN_COMMENT*) stan_table_find (k->comment, ins->address)) != NULL)
    {
      if (com->comment) stan_printf (FG_LWHITE, "%41s %s\n" RESET, ";", com->comment);
    }

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
  STAN_SYM     *_s1;

  if (!k) return -1;
  if (!sname) return -1;

  /* Find function by name*/
  if ((f = (STAN_SYM*) stan_table_find_by_name (k->func, sname)) == NULL)
    {
      if ((f = (STAN_SYM*) stan_table_find_by_name (k->sym, sname)) == NULL)
	{
	  fprintf (stderr, "- Cannot find function '%s'\n", sname);
	  return -1;
	}
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
  printf ("+ Disassembling function %s@%p\n", sname, (void*) f->addr);
  long addr1;
  addr1 = stan_ana_process_addr (k, f->addr);
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
	      printf ("+ Stopped after finding symbol '%s' (%d instructions)\n", _s1->id, cnt);
	      break;
	    }
	}
      if ((_s1 = (STAN_SYM*)stan_table_find (k->func, k->ins[j + 1].address)) != NULL) 
	{
	      printf ("+ Stopped after finding symbol '%s' (%d instructions)\n", _s1->id, cnt);
	      break;

	}

      cnt++;
    }

  stan_ana_close_dis (k);
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
  stan_ana_process_addr (k, addr);
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
  if (isprint (c[0]) && (isprint (c[1])) && (isprint (c[2]) || c[2]==0))
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
      //p += sprintf (p, "%p ", (int*)&c[0]);
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
		  snprintf (buffer, 1024, FG_BLUE " %lx(%s+%lx) " RESET " : " BG_RED "%s" RESET,
			    ptr, sec->id, rel, str);
	      else
		  snprintf (buffer, 1024, FG_BLUE " <%s> %lx(%s+%lx) " RESET " : " BG_RED "%s" RESET,
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
		  aux += snprintf (buffer, 1024, FG_GREEN " <%s> %lx(%s+0x%lx)" RESET,
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

  // Find closest symbol

  
  for (i = 0; i < len; i++)
    {
      // Resolve symbols!!
      s = stan_core_get_closest_symbol (k, p[i]);
      printf ("%p: %p\t", (void*) base + i*sizeof(long), (void*) p[i]);
      if (s)
	{
	  rel = p[i] - s->addr;
	  if (rel >= 0 && rel < 0x1000) // XXX: We have to actually checka against segment
	    printf ("<%s %+ld>", s->id, p[i] - s->addr);
	}
      printf ("\n");
      //if (((i > 0) & ((i % DUMP_WSIZE) == 0))) printf ("\n");
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

static int
_poke_bytes (long addr, char *str)
{
  int  i, l = strlen (str);
  char v, *p = str;
  l >>= 1; 

  v= 0;
  for (i = 0; i < l; i++)
    {
      sscanf (p, "%02x", (unsigned int *) &v);
      printf ("Wrote %02x to %p\n", (unsigned char)v, (void*)((unsigned char*)addr + i));
      *(unsigned char*)((unsigned char*)addr + i) = (unsigned char) v;

      p+=2;
    }
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
  if (!strcmp (fmt, "x")) _poke_bytes (ptr, str);
  else if (!strcmp (fmt, "s")) memcpy ((void*)ptr, (void*)str, strlen(str));
  else if (!strcmp (fmt, "p")) *((int *)ptr) = atoi (str);

  return 0;
}
