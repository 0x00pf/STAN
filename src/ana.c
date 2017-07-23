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

#include <capstone/capstone.h>

#include "cfg.h"
#include "core.h"

// XXX: This seems to be correct for functions
//      We need to change the code to process the .text segment
//      in chunks and disassemble functions independently
//      Also to allow on-the-fly disassembly from any address
//      
//      The ana module will remain but it has to do more stuff
//      and we will not store the code, but we will disassemble
//      every time the user asks for it
static long
_stan_configure_arm (STAN_CORE *k, long addr)
{
  if (!k) return -1;
  
  if (k->arch != STAN_CORE_ARCH_ARM) return addr;
  if (addr & 1)
    {
      cs_option(k->handle, CS_OPT_MODE, CS_MODE_THUMB);
      return (addr -1);
    }
  else
    cs_option(k->handle, CS_OPT_MODE, CS_MODE_ARM);
  return addr;
}

int
stan_ana_process_current_code (STAN_CORE *k)
{
  STAN_IMETA    *imeta;
  int           i;

  // Create Metadata array
  imeta = stan_imeta_new (k, NULL);

  if (k->count > 0)
    {
      /* Add functions and labels */
      size_t j;
      cs_insn *ins;
     
      /* Preliminary opcode analysis */

      for (j = 0; j < k->count; j++) 
	{
	  cs_detail *detail = k->ins[j].detail;

	  ins = &k->ins[j];
	  // XXX: this has to be platform independant
	  if (!strncasecmp (ins->mnemonic, "push", 4)) 
	    imeta[j].type = STAN_IMETA_PUSH;
	  else if (!strncasecmp (ins->mnemonic, "pop", 3)) 
	    imeta[j].type = STAN_IMETA_POP;
	  else if (!strncasecmp (ins->mnemonic, "mov", 3)) 
	    imeta[j].type = STAN_IMETA_MOV;
	  /* Comparision instructions */
	  else if (!strncasecmp (ins->mnemonic, "cmp", 3)) 
	    imeta[j].type = STAN_IMETA_CMP;
	  else if (!strncasecmp (ins->mnemonic, "test", 4)) 
	    imeta[j].type = STAN_IMETA_CMP;
	  else if (!strncasecmp (ins->mnemonic, "hlt", 3)) 
	    imeta[j].type = STAN_IMETA_RET;

	  // Check if address is a symbol
	  STAN_SYM *sym;
	  if ((sym = (STAN_SYM*) stan_table_find (k->sym, k->ins[j].address)) != NULL)
	    imeta[j].addr = sym;
	  
	  if (detail)
	    {
	      // Groups... Detect branches
	      for (i =0; i < detail->groups_count; i++)
		{
		  if (detail->groups[i] == CS_GRP_RET) 
		    {
		      imeta[j].type = STAN_IMETA_RET;
		    }
		  if (detail->groups[i] == CS_GRP_INT) 
		    {
		      imeta[j].type = STAN_IMETA_SYSCALL;
		    }
		  
		  if (detail->groups[i] == CS_GRP_CALL) 
		    {
		      if (k->arch == STAN_CORE_ARCH_X86)
			{
			  
			  if (detail->x86.operands[0].type == X86_OP_IMM)
			    sym = stan_core_add_func (k, detail->x86.operands[0].imm);
			  imeta[j].type = STAN_IMETA_CALL;
			  if (sym) imeta[j].tfunc = sym;
			}
		      else if (k->arch == STAN_CORE_ARCH_ARM)
			{
			  if (detail->arm.operands[0].type == ARM_OP_IMM)
			    sym = stan_core_add_func (k, detail->arm.operands[0].imm);
			  imeta[j].type = STAN_IMETA_JMP;
			  if (sym) imeta[j].tfunc = sym;
			}
		    }
		
		  if (detail->groups[i] == CS_GRP_JUMP)
		    {
		      if (k->arch == STAN_CORE_ARCH_X86)
			{
			  if (detail->x86.operands[0].type == X86_OP_IMM)
			    {
			      sym = stan_core_add_label (k, detail->x86.operands[0].imm);
			      if (sym) imeta[j].tlabel = sym;
			    }
			  imeta[j].type = STAN_IMETA_JMP;
			}
		      else if (k->arch == STAN_CORE_ARCH_ARM)
			{
			  if (detail->arm.operands[0].type == ARM_OP_IMM)
			    sym = stan_core_add_label (k, detail->arm.operands[0].imm);
			  imeta[j].type = STAN_IMETA_JMP;
			  if (sym) imeta[j].tlabel = sym;
			  
			}
		      
		    }
		  
		}
	    }
	}      
    }
  else
    {
      printf ("Error disassembling\n");
      k->count = 0;
    }

  stan_table_sort (k->func);
  stan_table_sort (k->label);

  return 0;
}


int
stan_ana_process_ep (STAN_CORE *k)
{
  STAN_IMETA    *imeta;
  int           i;


  if (k->arch != STAN_CORE_ARCH_X86) return 0;
  if (k->mode != STAN_CORE_MODE_64) return 0;
#if 0
  imeta = k->imeta;
  if (k->count > 0)
    {
      /* Add functions and labels */
      size_t j;
      cs_insn *ins;
     
      /* Preliminary opcode analysis */
      for (j = 0; j < k->count; j++) 
	{
	  cs_detail *detail = k->ins[j].detail;

	  ins = &k->ins[j];
	}
    }
  else
    {
      printf ("Error disassembling\n");
      k->count = 0;
    }

  stan_table_sort (k->func);
  stan_table_sort (k->label);
#endif
  return 0;
}


long
stan_ana_process_section ( STAN_CORE *k, STAN_SEGMENT *s)
{
  csh           handle;
  long          addr;

  if (!k) return -1;
  if (!s) return -1;
  if (k->valid != STAN_CORE_VALID) return -1;
  if ((handle = k->handle) == 0)
    {
      fprintf (stderr, "- Disassembler not initialised...\n");
      return -1;
    }

  if (!(s->type & STAN_SEGMENT_CODE)) return 1;

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);     
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  addr = _stan_configure_arm (k, s->addr);

  k->count = cs_disasm(handle, k->code + s->off, 
		       s->size, s->addr, 0, &k->ins);
  printf ("  * Analysing %ld instructions\n", k->count);
  // here we have got the code... now we can analyse it
  // whatever it is
  stan_ana_process_current_code (k);

  return addr;
}


long
stan_ana_process_addr (STAN_CORE *k, long addr)
{
  STAN_SEGMENT *s;
  int           i;
  csh           handle;
  long          rel, addr1;

  if (!k) return -1;
  if (k->valid != STAN_CORE_VALID) return -1;

  printf ("+ Analysing addres %p\n", (void*) addr);
  handle = k->handle;
  // FInd segment
  if ((i = stan_core_ptr_segment (k, addr)) < 0)
    {
      fprintf (stderr, "- invalid address");
      return -1;
    }
  s = (STAN_SEGMENT*) k->seg->p[i];
  if (!(s->type & STAN_SEGMENT_CODE)) return 1;

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);     
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  addr1 = _stan_configure_arm (k, addr);
  rel = addr - s->addr;
  k->count = cs_disasm(handle, k->code + s->off + rel, 
		       s->size - rel, addr1, 0, &k->ins);
  printf ("  * Analysing %ld instructions at (%p)\n", k->count, (void*)addr1);
  // here we have got the code... now we can analyse it
  // whatever it is
  stan_ana_process_current_code (k);

  return addr1;
}


int
stan_ana_init_dis (STAN_CORE *k)
{
  csh   handle;
  char  *val;
  int   syntax = CS_OPT_SYNTAX_INTEL;
  int   arch, mode;

  if (!k) return -1;
  if (k && k->valid == STAN_CORE_INVALID)
    {
      fprintf (stderr, "- ANA: Invalid core\n");
      return -1;
    }

  // Check config
  if ((val = stan_cfg_get ("syntax")))
    if (strncasecmp (val, "intel", 5))
	syntax = CS_OPT_SYNTAX_ATT;

  arch = stan_core_get_cs_arch (k);
  mode = stan_core_get_cs_mode (k);

  if (cs_open(arch, mode, &handle) != CS_ERR_OK)
    {
      fprintf (stderr, "Cannot start disassembler\n");
      return -1;
    }

  k->handle = handle;
  cs_option(handle, CS_OPT_SYNTAX, syntax);

  return 0;
}

int
stan_ana_close_dis (STAN_CORE *k)
{
  if (!k) return -1;
  if (k->ins)
    {
      cs_free (k->ins, k->count);
      k->ins = NULL;
      k->count = 0;
    }
  if (k->imeta)
    {
      free(k->imeta);
      k->imeta = NULL;
    }
  if (k->handle)
    cs_close (&k->handle);
  
  k->handle = 0;

  return 0 ;
}

int  
stan_ana_init (STAN_CORE *k)
{
  int   i;

  printf ("Starting analysis\n");

  stan_ana_init_dis (k);
  // Check if there are sections... otherwise use segment
  STAN_SEGMENT *c;
  if (k->sec->n == 0)
    {
      printf ("+ No section found... using segments\n");
      for (i = 0; i < k->seg->n; i++)
	{
	  c = (STAN_SEGMENT*) stan_segment_clone ((STAN_SEGMENT*)k->seg->p[i]);
	  stan_table_add (k->sec, (STAN_ITEM*) c);
	}
    }
  printf ("+ Processing %d sections/segments\n", k->sec->n);
  // Process sections
  for (i = 0; i < k->sec->n; i ++)
    {
      c = (STAN_SEGMENT*) k->sec->p[i];
      printf ("+ Processing section [%d] '%s'\n", i, c->id);
      stan_ana_process_section (k, c);
    }

  // Process entry point
  stan_ana_process_addr (k, k->ep);
  stan_ana_process_ep (k);

  stan_table_sort (k->func);
  stan_table_sort (k->label);
  stan_ana_close_dis (k);
  // Done
  return 0;
}

