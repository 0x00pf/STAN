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
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#include <elf.h>

#include "core.h"
#include "symb.h"
#include "elf32.h"


void
stan_elf32_process_segments (STAN_CORE *k)
{
  Elf32_Ehdr*  elf_hdr;
  Elf32_Phdr*  elf_seg;
  int          n_seg;
  int          i, n = 0;
  STAN_SEGMENT *seg;
  char         buffer[1024];
 
  elf_hdr = (Elf32_Ehdr *) k->code;
  n_seg = elf_hdr->e_phnum;
  elf_seg = (Elf32_Phdr *) ((unsigned char*) elf_hdr 
			    + (unsigned int) elf_hdr->e_phoff);

  for (i = 0; i < n_seg; i++)
    {    
      if (elf_seg->p_type == PT_LOAD)
	{
	  seg = stan_segment_new ();
	  seg->addr = elf_seg->p_vaddr;
	  seg->off = elf_seg->p_offset;
	  seg->size = elf_seg->p_filesz;
	  if (elf_seg->p_flags & 0x011)
	    seg->type = STAN_SEGMENT_CODE; // .text
	  else
	    seg->type = STAN_SEGMENT_DATA; // .data

	  snprintf (buffer, 1024, "%s_%02d", 
		    seg->type == STAN_SEGMENT_CODE ? "text" : "data", n);
	  seg->id = strdup (buffer);
	  stan_table_add (k->seg, (STAN_ITEM*)seg);
	  n++;
	}
      elf_seg = (Elf32_Phdr *) ((unsigned char*) elf_seg 
			    + (unsigned int) elf_hdr->e_phentsize);
    }
  printf ("+ %d segments processed\n", n);
  
}



void
stan_elf32_process_symtab (STAN_CORE *k, Elf32_Shdr* s)
{
  char *sname;
  int n_entries;
  int  i;
  void *data = k->code;
  Elf32_Ehdr* elf_hdr = (Elf32_Ehdr *) data;
  Elf32_Shdr *shdr = (Elf32_Shdr *)(data + elf_hdr->e_shoff);
  const char *const sh_strtab_p = (char *)(data + shdr[s->sh_link].sh_offset);
  const char *const sh_symtab_p = data + s->sh_offset;
  Elf32_Sym *symbol;
  STAN_SYM  *ssym;
#ifdef DEBUG
  printf ("  -> Addr: %8x Offset: %8x  Size:%8x\n", 
	  s->sh_addr, s->sh_offset, s->sh_size);
#endif
  n_entries = s->sh_size / s->sh_entsize;
#ifdef DEBUG
  printf ("  + %d symbols in symtab\n", n_entries);
#endif
  for (i = 0; i < n_entries; i++)
    {
      symbol = &((Elf32_Sym *)sh_symtab_p)[i];
     
      if (symbol->st_name)
	sname = (char*) (sh_strtab_p + symbol->st_name);
      else
	sname = "NONAME";

      ssym = stan_sym_new (sname, symbol->st_value);
      stan_table_add (k->sym, (STAN_ITEM*)ssym);

      if (ELF32_ST_TYPE(symbol->st_info) == STT_FUNC)
	{
	  ssym->type = STAN_SYM_TYPE_FUNC;
	}
    }
}


void
stan_elf32_process_dynsymtab (STAN_CORE *k, Elf32_Shdr* s)
{
  void       *data = k->code;
  int        n_entries;
  int        i;
  Elf32_Ehdr *elf_hdr = (Elf32_Ehdr *) data;
  Elf32_Shdr *shdr = (Elf32_Shdr *)(data + elf_hdr->e_shoff);
  const char *const sh_strtab_p = (char *)(data + shdr[s->sh_link].sh_offset);
  const char *const sh_symtab_p = data + s->sh_offset;
  Elf32_Sym  *symbol;
  STAN_SYM   *ssym;
  char       buffer[1024];

  n_entries = s->sh_size / s->sh_entsize;
  for (i = 0; i < n_entries; i++)
    {
      symbol = &((Elf32_Sym *)sh_symtab_p)[i];

      if (symbol->st_name)
	snprintf (buffer, 1024, "%s@plt", (char*) (sh_strtab_p + symbol->st_name));
      else
	strcpy (buffer, "NONAME");

      printf ("%02d %s %8x\n", i, buffer, symbol->st_value);
      ssym = stan_sym_new (buffer, symbol->st_value);
      stan_table_add_dups (k->dsym, (STAN_ITEM*)ssym);
    }
}



void
stan_elf32_process_rela (STAN_CORE *k, Elf32_Shdr* s)
{
  void              *data = k->code;
  int               n_entries;
  int               i, indx;
  const char *const sh_reltab_p = data + s->sh_offset;
  Elf32_Rel         *rel;
  STAN_SYM          *ssym;

  n_entries = s->sh_size / s->sh_entsize;
  if (!k->dsym->p) return;
  for (i = 0; i < n_entries; i++)
    {
      rel = &((Elf32_Rel*)sh_reltab_p)[i];
      indx = ELF32_R_SYM(rel->r_info);
      


	  ssym = (STAN_SYM *) k->dsym->p[indx];
 
	  if (ssym) ssym->addr = rel->r_offset;

    }
}



void
stan_elf32_process_sections (STAN_CORE *k)
{
  char         *sname;
  int          i, _n_sec = 0;
  Elf32_Ehdr*  elf_hdr;
  Elf32_Shdr   *shdr;
  Elf32_Shdr   *sh_strtab;
  char         *sh_strtab_p;
  STAN_SEGMENT *sec;
  STAN_SYM     *ssym;

  elf_hdr = (Elf32_Ehdr *) k->code;
  shdr = (Elf32_Shdr *)(k->code + elf_hdr->e_shoff);
  sh_strtab = &shdr[elf_hdr->e_shstrndx];
  sh_strtab_p = k->code + sh_strtab->sh_offset;

   
  for (i = 0; i < elf_hdr->e_shnum; i++)
    {
      if (shdr[i].sh_type == SHT_PROGBITS && shdr[i].sh_addr != 0)
	{
	  sname = (char*) (sh_strtab_p + shdr[i].sh_name);
	  sec = stan_segment_new ();

	  sec->id = strdup (sname);
	  sec->type = 0;
	  if (shdr[i].sh_flags & SHF_ALLOC) sec->type |= STAN_SEGMENT_DATA;
	  if (shdr[i].sh_flags & SHF_WRITE) sec->type |= STAN_SEGMENT_WRITE;
	  if (shdr[i].sh_flags & SHF_EXECINSTR) sec->type |= STAN_SEGMENT_CODE;
	  else sec->type = STAN_SEGMENT_DATA | STAN_SEGMENT_WRITE;
	  sec->addr = shdr[i].sh_addr;
	  sec->off = shdr[i].sh_offset;
	  sec->size = shdr[i].sh_size;
	  //sec->esize = shdr[i].sh_entsize;
	  sec->esize = elf_hdr->e_shentsize;

	  // Store Section
	  stan_table_add (k->sec, (STAN_ITEM*)sec);
	  // Create symbol for the section
	  ssym = stan_sym_new (sec->id, sec->addr);
	  stan_sym_add_type (ssym, STAN_SYM_TYPE_SECTION);
	  stan_table_add (k->sym, (STAN_ITEM*) ssym);
	  _n_sec++;
	}

      else if (shdr[i].sh_type == SHT_SYMTAB)
	{
	  stan_elf32_process_symtab (k, &shdr[i]);
	  k->flags |= STAN_CORE_FLAGS_NOT_STRIPPED;
	}
      else if (shdr[i].sh_type == SHT_DYNSYM)
	{
	  stan_elf32_process_dynsymtab (k, &shdr[i]);
	  k->flags |= STAN_CORE_FLAGS_DYNAMIC;
	}
      else if (shdr[i].sh_type == SHT_REL)
	{
	  stan_elf32_process_rela (k, &shdr[i]);
	}      

    }

  // process GOT.PLT
  // XXX: Memory corruption is here 
  for (i =0; i < _n_sec; i++)
    {
      sec = (STAN_SEGMENT*)k->sec->p[i];
     if (k->arch == STAN_CORE_ARCH_ARM)
       {
	 if (strstr (sec->id, ".got"))
	   {
	     int k1 = sec->size / sec->esize;
	     printf ("Adjusting dynamic symbols as per binary '%s' (%d entries)\n", 
		     sec->id, k1);

	     int j;

	     for (j = 0; j < k1; j++)
	       {
		 long ptr = (long)((unsigned char*)k->code + sec->off + j*sec->esize);
		 long plt_ptr = (long)*((int *)ptr) - 6;
		 long got_ptr = (long)((unsigned char*)sec->addr + j*sec->esize);
		 long plt_ptr1 = plt_ptr + 12* j - 10;

		 STAN_SYM* ssym = (STAN_SYM*) stan_table_find (k->dsym, got_ptr);
		 STAN_SYM* ssym1;
		 if (ssym) 
		   {
		     ssym1 = stan_sym_clone (ssym);
		     ssym1->addr = plt_ptr1;
		     stan_table_add (k->sym, (STAN_ITEM*) ssym1);
		   }
	       }
	   }
       }
     else if (k->arch == STAN_CORE_ARCH_X86)
       {
	 if (strstr (sec->id, ".got"))
	   {
	     int k1 = sec->size / sec->esize;
	     printf ("Adjusting dynamic symbols as per binary '%s' (%d entries)\n", 
		     sec->id, k1);
	     
	     int j;

	     for (j = 0; j < k1; j++)
	       {
		 long ptr = (long)((unsigned char*)k->code + sec->off + j*sec->esize);
		 long plt_ptr = (long)(*((int *)ptr) - 6);
				 long got_ptr = (long)((unsigned char*)sec->addr + j*sec->esize);

				 STAN_SYM* ssym = (STAN_SYM*) stan_table_find (k->dsym, got_ptr);
		 STAN_SYM* ssym1;
		 if (ssym) 
		   {
		     ssym1 = stan_sym_clone (ssym);
		     ssym1->addr = plt_ptr;
		     stan_table_add (k->sym, (STAN_ITEM*) ssym1);
		   }
		
	       }
	   }
	 
       }
    }
  
  return;
}



/*
 * ------------------------------------------------
 * Plug-in interface
 *-------------------------------------------------
 */

int  
stan_elf32_init (STAN_CORE *k)
{
  Elf32_Ehdr* elf_hdr;

  printf ("+ Processing Core...\n");

  elf_hdr = (Elf32_Ehdr *) k->code;

  // Check that the core is VALID (is identified)
  if (k->valid == STAN_CORE_INVALID)
    {
      fprintf (stderr, "- Incalid Core. Try to identify first\n");
      return -1;
    }
  // Extract Segments
  stan_elf32_process_segments (k);
  stan_table_sort (k->seg);

  // Extract Sections
  stan_elf32_process_sections (k);
  stan_table_sort (k->sec);

  // Add Entry point symbol
  STAN_SYM *ep = stan_sym_new ("__entry_point", elf_hdr->e_entry);
  ep->type= STAN_SYM_TYPE_FUNC;
  stan_table_add (k->sym, (STAN_ITEM*) ep);
  stan_table_sort (k->sym);
  STAN_SYM *aux = stan_sym_clone (ep);
  stan_table_add (k->func, (STAN_ITEM*)aux);
  stan_table_sort (k->func);

  return 0;
}

int  
stan_elf32_process (STAN_CORE *k)
{
  // Process Sections 
  // GEt configuration: colors, Intel/AT&T,...
  // If no section define, create a section from the executable segments
  // XXX: Check if we can add code in segment out of a section
  //      
  // Disassemble & process
  //  - Add labels
  //  - Add functions
  // Further analysis -> This is not ELF related.... move somewhere else
  //   - Create symbol for entry point
  //   - try to find main
  //   - Try to figure out functions scope...
  return 0;
}

