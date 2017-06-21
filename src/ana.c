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

static int
stan_ana_section (csh handle, STAN_CORE *k, STAN_SEGMENT *s)
{
  STAN_IMETA    *imeta;
  int           i;

  if (!k) return -1;
  if (!s) return -1;
  if (k->valid != STAN_CORE_VALID) return -1;


  if (!(s->type & STAN_SEGMENT_CODE)) return 1;

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);     
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  s->count = cs_disasm(handle, k->code + s->off, 
		       s->size, s->addr, 0, &s->ins);
  printf ("  * Analysing %ld instructions\n", s->count);
  // Create Metadata array
  imeta = stan_imeta_new (k, s);

  if (s->count > 0)
    {
      /* Add functions and labels */
      size_t j;
      cs_insn *ins;
      

      /* Preliminary opcode analysis */

      for (j = 0; j < s->count; j++) 
	{
	  cs_detail *detail = s->ins[j].detail;

	  ins = &s->ins[j];
	  // XXX: this has to be platform independant
	  if (!strncasecmp (ins->mnemonic, "push", 4)) 
	    imeta[j].type = STAN_IMETA_PUSH;
	  else if (!strncasecmp (ins->mnemonic, "pop", 3)) 
	    imeta[j].type = STAN_IMETA_POP;
	  else if (!strncasecmp (ins->mnemonic, "mov", 3)) 
	    imeta[j].type = STAN_IMETA_MOV;
	  /* Comparission instructions */
	  else if (!strncasecmp (ins->mnemonic, "cmp", 3)) 
	    imeta[j].type = STAN_IMETA_CMP;
	  else if (!strncasecmp (ins->mnemonic, "test", 4)) 
	    imeta[j].type = STAN_IMETA_CMP;
	  else if (!strncasecmp (ins->mnemonic, "hlt", 3)) 
	    imeta[j].type = STAN_IMETA_RET;

	  // Check if address is a symbol
	  STAN_SYM *sym;
	  if ((sym = (STAN_SYM*) stan_table_find (k->sym, s->ins[j].address)) != NULL)
	    s->imeta[j].addr = sym;
	  
	  if (detail)
	    {
	      // Groups... Detect branches
	      for (i =0; i < detail->groups_count; i++)
		{
		  if (detail->groups[i] == CS_GRP_RET) 
		    {
		      s->imeta[j].type = STAN_IMETA_RET;
		    }
		  if (detail->groups[i] == CS_GRP_INT) 
		    {
		      s->imeta[j].type = STAN_IMETA_SYSCALL;
		    }
		  
		  if (detail->groups[i] == CS_GRP_CALL) 
		    {
		      if (detail->x86.operands[0].type == X86_OP_IMM)
			sym = stan_core_add_func (k, detail->x86.operands[0].imm);
		      s->imeta[j].type = STAN_IMETA_CALL;
		      if (sym) s->imeta[j].tfunc = sym;
		    }
		  if (detail->groups[i] == CS_GRP_JUMP)
		    {
		      if (k->arch == STAN_CORE_ARCH_X86)
			{
			  
			  //if (detail->x86.operands[0].type == CS_OP_IMM)
			  if (detail->x86.operands[0].type == X86_OP_IMM)
			    sym = stan_core_add_label (k, detail->x86.operands[0].imm);
			  s->imeta[j].type = STAN_IMETA_JMP;
			  if (sym) s->imeta[j].tlabel = sym;
			  
			}
		      else if (k->arch == STAN_CORE_ARCH_ARM)
			{
			  if (detail->arm.operands[0].type == ARM_OP_IMM)
			    sym = stan_core_add_label (k, detail->arm.operands[0].imm);
			  s->imeta[j].type = STAN_IMETA_JMP;
			  if (sym) s->imeta[j].tlabel = sym;
			  
			}
		      
		    }
		  
		  
		}
	    }
	}      
    }
  else
    {
      printf ("Error disassembling section <%s>\n", s->id);
      s->count = 0;
    }
  
  return 0;
}

int  
stan_ana_init (STAN_CORE *k)
{
  csh handle;
  int i;
  char  *val;
  int   syntax = CS_OPT_SYNTAX_INTEL;
  int   arch, mode;

  printf ("Starting analysis\n");
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
      stan_ana_section (handle, k, c);
    }

  stan_table_sort (k->func);
  stan_table_sort (k->label);
  // Done
  return 0;
}

