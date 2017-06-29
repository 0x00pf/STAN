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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// open
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// close
#include <unistd.h>
//mmap
#include <sys/mman.h>

// elf 
// TODO: Move into a plug-in in future
#include <elf.h>

#include <capstone/capstone.h>

// STAN
#include "utils.h"
#include "core.h"
#include "symb.h"

// Binary Plug-ins
#include "elf64.h"
#include "elf32.h"

// Constants to string arrays
static char *stan_core_type_str[] = {"Unknown", "ELF64", "ELF32", "RAW", NULL};
static char *stan_core_os_str[] = {"Unknown", "BareMetal", "Linux", NULL};
static char *stan_core_arch_str[] = {"Unknown", "X86", "ARM", NULL};
static int  capstone_arch[] = {CS_ARCH_MAX, CS_ARCH_X86, CS_ARCH_ARM, -1};
static char *stan_core_mode_str[] = {"Unknown", "32bits", "64bits", "ARM32", "ARM-Thumb", NULL};
static int  capstone_mode[] = {-1, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, CS_MODE_THUMB, -1};
static char *stan_core_valid_str[] = {"INVALID", "VALID", NULL};

char *
stan_core_get_os_name (STAN_CORE *k)
{
  return stan_core_os_str[k->os];
}

char *
stan_core_get_arch_name (STAN_CORE *k)
{
  return stan_core_arch_str[k->arch];
}

char *
stan_core_get_mode_name (STAN_CORE *k)
{
  return stan_core_mode_str[k->mode];
}


static void
_stan_print_array (char* p[])
{
  int i = 0;

  printf ("(");
  while (p[i + 1])
    printf ("%s, ", p[i++]);
  printf ("%s", p[i]);
  printf (")\n");
}

int           
stan_core_get_cs_arch (STAN_CORE *k)
{
  return capstone_arch[k->arch];
}

int           
stan_core_get_cs_mode (STAN_CORE *k)
{
  return capstone_mode[k->mode];
}

static int _st_seg_alloc = 0;
static int _st_seg_free = 0;


STAN_SEGMENT *
stan_segment_new ()
{
  STAN_SEGMENT *sg;
  if ((sg = malloc (sizeof (STAN_SEGMENT))) == NULL)
    {
      fprintf (stderr, "- Cannot allocate memory for segment\n");
      return NULL;
    }
  memset (sg, 0, sizeof (STAN_SEGMENT));
  _st_seg_alloc ++;
  //printf ("!! SEG Allocs: %d Frees:%d\n", _st_seg_alloc, _st_seg_free);

  return sg;
}


int           
stan_segment_free (STAN_SEGMENT *sg)
{
  if (!sg) return -1;

  if (sg->id) free (sg->id);
  free (sg);
  _st_seg_free ++;

  return 0;
}

/* XXX: This function doesn not clone opcodes!!!! */
STAN_SEGMENT *
stan_segment_clone (STAN_SEGMENT *s)
{
  STAN_SEGMENT *c;

  c = stan_segment_new ();
  c->addr = s->addr;
  c->id = strdup (s->id);
  c->type = s->type;
  c->off = s->off;
  c->size = s->size;
  c->esize = s->esize;
  c->a0 = s->a0;
  c->a1 = s->a1;
  c->p = s->p;

  return c;
}

int        
stan_core_init ()
{
  // register core readers
  // no plug-in implementations yet
  return 0;
}

STAN_CORE *
stan_core_new ()
{
  STAN_CORE *k;
  
  if ((k = malloc (sizeof(STAN_CORE))) == NULL)
    {
      fprintf (stderr, "- Cannot allocate memory for core object\n");
      return NULL;
    }
  // Initialises pointers and set fields to UNKNOWN/INVALID
  memset (k, 0, sizeof(STAN_CORE)); 
  k->fd = -1;
  
  k->seg = stan_table_new ((STAN_ITEM_FREE)stan_segment_free, sizeof(STAN_SEGMENT*));
  k->sec = stan_table_new ((STAN_ITEM_FREE)stan_segment_free,sizeof(STAN_SEGMENT*));

  k->sym = stan_table_new ((STAN_ITEM_FREE)stan_sym_free, sizeof(STAN_SYM*));
  k->dsym = stan_table_new ((STAN_ITEM_FREE)stan_sym_free, sizeof(STAN_SYM*));
  k->func = stan_table_new ((STAN_ITEM_FREE)stan_sym_free,sizeof(STAN_SYM*));
  k->label = stan_table_new ((STAN_ITEM_FREE)stan_sym_free,sizeof(STAN_SYM*));
  k->comment = stan_table_new ((STAN_ITEM_FREE)stan_comment_free,sizeof(STAN_SYM*));

  return k;
}

int        
stan_core_free (STAN_CORE *k)
{
  if (!k) return -1;
  if (k->fname) free (k->fname);
  if (k->fd >=0) close (k->fd);

  munmap (k->code, k->size);
  close (k->fd);

  stan_table_free (k->seg);
  stan_table_free (k->sec);
  stan_table_free (k->sym);
  stan_table_free (k->dsym);
  stan_table_free (k->func);
  stan_table_free (k->label);
  stan_table_free (k->comment);

  free (k);
  return -1;
}


int        
stan_core_clean (STAN_CORE *k)
{
  if (!k) return -1;
  if (k->fname) free (k->fname);
  if (k->fd >=0) close (k->fd);

  printf ("+ Cleanning up core\n");

  printf ("+ Deleting Segments....\n");
  stan_table_free (k->seg);
  printf ("+ Deleting Sections....\n");
  stan_table_free (k->sec);
  printf ("+ Deleting Symbols....\n");
  stan_table_free (k->sym);
  stan_table_free (k->dsym);
  stan_table_free (k->func);
  stan_table_free (k->label);
  stan_table_free (k->comment);

  munmap (k->code, k->size);
  close (k->fd);
  memset (k, 0, sizeof(STAN_CORE)); 

  k->fd = -1;
  k->l_cnt = 0;

  k->seg = stan_table_new ((STAN_ITEM_FREE)stan_segment_free, sizeof(STAN_SEGMENT*));
  k->sec = stan_table_new ((STAN_ITEM_FREE)stan_segment_free,sizeof(STAN_SEGMENT*));

  k->sym = stan_table_new ((STAN_ITEM_FREE)stan_sym_free, sizeof(STAN_SYM*));
  k->dsym = stan_table_new ((STAN_ITEM_FREE)stan_sym_free, sizeof(STAN_SYM*));
  k->func = stan_table_new ((STAN_ITEM_FREE)stan_sym_free,sizeof(STAN_SYM*));
  k->label = stan_table_new ((STAN_ITEM_FREE)stan_sym_free,sizeof(STAN_SYM*));
  k->comment = stan_table_new ((STAN_ITEM_FREE)stan_comment_free,sizeof(STAN_SYM*));

  return -1;
}



int        
stan_core_load (STAN_CORE *k, char *fname)
{
  int l;
  if (!k) return -1;
  if (!fname) return -1;

  printf ("+ Opening file '%s'\n", fname);
  //if ((k->fd = open (fname, O_RDWR)) < 0)
  if ((k->fd = open (fname, O_RDONLY)) < 0)
    {
      perror ("open");
      return -1;
    }
  k->size = stan_util_get_file_size (k->fd);
  /*
    // XXX: Keep for the patching function. To Be Implemented
  if ((k->code = mmap (NULL, k->size, PROT_READ, //| PROT_WRITE,
		       MAP_SHARED, k->fd, 0)) == MAP_FAILED)
    {
      perror ("mmap:");
      exit (1);
    } 
  */
  k->code = malloc (k->size);
  l = read (k->fd, k->code, k->size);
  if (l < k->size)
    {
      fprintf (stderr, "... you lazy boy... do the proper reading!\n");
      exit (1);
    }
  close (k->fd);


  k->fname = strdup (fname);
  k->valid = STAN_CORE_VALID;
  printf ("+ Loaded '%s' %ld bytes\n", k->fname, k->size);
  
  return -1;
}

int        
stan_core_save (STAN_CORE *k, char *fname)
{
  if (!k) return -1;

  fprintf (stderr, "%s: Function not yet implemented\n", __FUNCTION__);
  return -1;
}

int 
stan_core_dump (STAN_CORE *k)
{
  int   i;

  printf ("+ Core Information\n");
  printf ("  - File         : %s\n", k->fname);
  printf ("  - Size         : %ld\n", k->size);
  printf ("  - Entry Point  : %lx\n", k->ep);
  printf ("  - Type         : %s\n", stan_core_type_str[k->type]);
  printf ("  - Valid        : %s\n", stan_core_valid_str[k->valid]);
  //printf ("  - OS           : %s\n", stan_core_os_str[k->os]);
  printf ("  - Architecture : %s\n", stan_core_arch_str[k->arch]);
  printf ("  - Mode         : %s(%d)\n", stan_core_mode_str[k->mode], k->mode);
  printf ("  - Info         : %s %s\n", IS_DYNAMIC(k) ? "Dynamic" : "Static",
	  IS_STRIPPED(k) ? "Stripped" : "Not Stripped"
	  );


  // Dump Segments
  for (i = 0; i < k->seg->n; i++)
    {
      STAN_SEGMENT *s = (STAN_SEGMENT*) k->seg->p[i];
      printf ("[%02d] %s Addr:%p Offset:0x%04lx Size:0x%04lx (%ld)\n",
	      i,
	      //s->type == STAN_SEGMENT_CODE ? "text" : "data",
	      s->id,
	      (void*)s->addr, s->off, s->size, s->size
	      );
    }
  // Dump Sections
  printf (".................................................\n");
  for (i = 0; i < k->sec->n; i++)
    {
      STAN_SEGMENT *s = (STAN_SEGMENT*) k->sec->p[i];
      STAN_SEGMENT *s1 = NULL;
      int seg = stan_core_ptr_segment (k, s->addr);
      if (seg >=0) s1 = (STAN_SEGMENT*)k->seg->p[seg];

      printf ("[%02d] %15s 0x%02x Addr:%p Offset:0x%04lx Size:0x%04lx (%7ld) [%s+0x%04lx]\n",
	      i,
	      s->id,
	      s->type,
	      (void*)s->addr, s->off, s->size, s->size,
	      (s1) ? s1->id : "N/A",
	      (s1) ? s->addr - s1->addr : 0
	      );
    }

  return 0;
}

int
stan_core_dump_symbols (STAN_CORE *k)
{
  int i;
  int n;
  STAN_SYM *s;

  if (!k) return -1;
  n = k->sym->n;
  printf ("+ %d Symbols in core\n", n);
  for (i = 0; i < n; i++)
    {
      s = (STAN_SYM*) k->sym->p[i];
      if (s->type & STAN_SYM_TYPE_SECTION) putchar ('S'); else putchar (' ');
      if (s->type & STAN_SYM_TYPE_FUNC) putchar ('F'); else putchar (' ');
      if (s->type & STAN_SYM_TYPE_LABEL) putchar ('L'); else putchar (' ');
      printf (" %p %40s\n", (void*)s->addr, s->id);
    }
  n = k->dsym->n;
  printf ("+ %d Dynamic Symbols in core\n", n);
  for (i = 0; i < n; i++)
    {
      s = (STAN_SYM*) k->dsym->p[i];
      if (s->type & STAN_SYM_TYPE_SECTION) putchar ('S'); else putchar (' ');
      if (s->type & STAN_SYM_TYPE_FUNC) putchar ('F'); else putchar (' ');
      if (s->type & STAN_SYM_TYPE_LABEL) putchar ('L'); else putchar (' ');
      printf (" %p %40s\n", (void*)s->addr, s->id);
    }
  return 0;
}

int
stan_core_set (STAN_CORE *k, int arch, int mode, int os)
{
  if (!k) return -1;
  

  if (!STAN_CHECK_RANGE(arch, 0, STAN_CORE_ARCH_LAST))
    {
      fprintf (stderr, "- Invalid Architecture. Supported architectures: ");
      _stan_print_array (stan_core_arch_str);
      return -1;
    }
  if (!STAN_CHECK_RANGE(mode, 0, STAN_CORE_MODE_LAST))
    {
      fprintf (stderr, "- Invalid Mode. Supported Modes: ");
      _stan_print_array (stan_core_mode_str);
      return -1;
    }


  if (!STAN_CHECK_RANGE(os, 0, STAN_CORE_OS_LAST))
    {
      fprintf (stderr, "- Invalid OS. Supported OS: ");
      _stan_print_array (stan_core_os_str);
      return -1;
    }

  printf ("+ Manual Setting Arch:%s Mode:%s OS:%s\n", 
	  stan_core_arch_str[arch], 
	  stan_core_mode_str[mode], 
	  stan_core_os_str[os]);

  k->arch = arch;
  k->mode = mode;
  k->os = os;
  return 0;
}

int        
stan_core_identify (STAN_CORE *k)
{
  Elf64_Ehdr*  elf_hdr64 = NULL;
  Elf32_Ehdr*  elf_hdr32 = NULL;

  if (!k) return -1;
  if (k->valid == STAN_CORE_INVALID)
    {
      printf ("- Trying to identify an invalid core\n");
      return -1;
    }

  // Here we should call all the plug-ins... but we do not have
  // plug-ins yet... so lets put the ELF code just here :)
  // For now it is just ELF or RAW
  unsigned char *p = k->code;
  if (!(p[0] == 0x7f && p[1] == 0x45 && p[2] == 0x4c && p[3] == 0x46))
    {
      k->type = STAN_CORE_TYPE_RAW;
      // For RAW we cannot do much.... the user has to set the 
      // architecture and mode
      return 0;
    }
  // Otherwise it is ELF and we process it
  // TODO: Refactor all this whenever the plugin system is in place
  elf_hdr64 = (Elf64_Ehdr *) k->code;
  elf_hdr32 = (Elf32_Ehdr *) k->code;

  // TODO: For now we only support Linux
  k->os = STAN_CORE_OS_LINUX;
  k->arch = STAN_CORE_ARCH_X86;
  k->mode = STAN_CORE_MODE_64;
  k->type = STAN_CORE_TYPE_ELF_64;

  k->core_init = stan_elf64_init;
  k->core_process = stan_elf64_process;
  printf ("+ ELF Machine ID: %d\n", elf_hdr64->e_machine);

  switch (elf_hdr64->e_machine)
    {
    case EM_386:
      {
	k->mode = STAN_CORE_MODE_32;
	k->type = STAN_CORE_TYPE_ELF_32;
	k->core_init = stan_elf32_init;
	k->core_process = stan_elf32_process;
	k->ep = elf_hdr32->e_entry;

	break;
      }
    case EM_X86_64:
      {
	k->ep = elf_hdr64->e_entry;
	break;
      }
    case EM_ARM:
      {
	k->arch = STAN_CORE_ARCH_ARM;

	k->type = STAN_CORE_TYPE_ELF_32;
	k->ep = elf_hdr32->e_entry;
	// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/arm/kernel/elf.c
	k->mode = STAN_CORE_MODE_ARM;
	k->core_init = stan_elf32_init;
	k->core_process = stan_elf32_process;

	//mod_add_sym ("entry", elf_hdr1->e_entry);
	break;
      }
#ifdef EM_AARCH64
    case EM_AARCH64:
      {
	k->arch = CS_ARCH_ARM64;
	k->mode = CS_MODE_ARM;
	break;
      }
#endif
    }
  printf ("+ Arch: %d Mode:%d Type: %d\n", k->arch, k->mode, k->type);
  k->core_init (k); 
  
  return -1;
}


// XXX: Functions are labels are stored as symbols
//      But in separated tables???... does it make sense?
static STAN_SYM*           
_stan_core_add_sitem (STAN_CORE *k, STAN_TABLE *t, long addr, char* prefix)
{
  STAN_SYM   *s;
  STAN_SYM   *f;
  char       sname[1024];

  if (!k) return NULL;

  if (!addr) return NULL;  // We are not interested in NULL
  // Check if item already exists
  if ((s = (STAN_SYM*) stan_table_find (t, addr)) != NULL) return s;

  // Create the new symbol

  memset (sname, 0, 1024);
  // If not ... check if a symbol references it and use for name
  if ((s = (STAN_SYM*) stan_table_find (k->sym, addr)) == NULL)
    {
      if (prefix[0] == 'l')
	{
	  snprintf (sname, 1024, "%s%d", prefix, k->l_cnt);      
	  k->l_cnt++;
	}
      else
	snprintf (sname, 1024, "%s_%lx", prefix, addr);      
    }
  else snprintf (sname, 1024, "%s", s->id);

  f = stan_sym_new (sname, addr);

  stan_table_add (t, (STAN_ITEM*) f);
  // otherwise create a name
  // add item to proper table with generated name

  return f;
}


STAN_SYM*
stan_core_add_func (STAN_CORE *k, long addr)
{
  STAN_SYM *s, *s1;

  if (!k) return NULL;

  if ((s = _stan_core_add_sitem (k, k->func, addr, "func")))
    {
      s1 = (STAN_SYM*) stan_sym_clone (s);
      stan_table_add (k->sym, (STAN_ITEM*)s1);
      stan_table_sort (k->sym);
      stan_table_sort (k->func);
    }
  
  return s;
}

STAN_SYM*
stan_core_add_label (STAN_CORE *k, long addr)
{
  if (!k) return NULL;

  return _stan_core_add_sitem (k, k->label, addr, "l");
}

static int
_stan_core_dump_sym_table (STAN_CORE *k, STAN_TABLE *t)
{
  int i;
  STAN_SYM *s;

  if (!k) return -1;
  if (!t) return -1;

  for (i = 0; i < t->n; i++)
    {
      s = (STAN_SYM*) t->p[i];
      printf ("%p\t\t%s\n", (void*) s->addr, s->id);
    }
  return 0;
}

int
stan_core_dump_func (STAN_CORE *k)
{
  return _stan_core_dump_sym_table (k, k->func);
}

int
stan_core_dump_label (STAN_CORE *k)
{
  return _stan_core_dump_sym_table (k, k->label);

}



int
stan_comment_free (STAN_COMMENT *c)
{
  if (!c) return -1;
  if (c->id) free (c->id);
  if (c->comment) free (c->comment);
  return 0;
}


STAN_IMETA   *
stan_imeta_new (STAN_CORE *k, STAN_SEGMENT *s)
{
  if (!k) return NULL;

  if (k->count <= 0) return NULL;
  //XXX: IMETA struct only holds pointer to symbols referenced in other tables
  //     we do not have to delete them
  if (k->imeta) free (k->imeta);
  k->imeta = NULL;

  if ((k->imeta = malloc (sizeof(STAN_IMETA) * k->count)) == NULL)
    {
      fprintf (stderr, "- Cannot allocate metadata for instructions\n");
      return NULL;
    }
  memset (k->imeta, 0, sizeof(STAN_IMETA) * k->count);

  return k->imeta;
}

// TO be moved to core_utils.c

int
stan_core_ptr_segment (STAN_CORE *k, long addr)
{
  int i, n;
  STAN_SEGMENT *s;

  n = k->seg->n;
  for (i = 0; i < n; i++)
    {
      s = (STAN_SEGMENT*) k->seg->p[i];
      if (addr >= s->addr && addr <= (s->addr + s->size)) return i;
    }
  return -1;
}


int           
stan_core_rename_func_at (STAN_CORE *k, long addr, char *name)
{
  STAN_SYM *s;

  if (!k) return -1;
  if (!name) return -1;
  if (!addr) return -1;

  if ((s = (STAN_SYM*)stan_table_find (k->func, addr)))
    {
      printf (" + Found function %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "Function '%s' not found\n", name);
    }
  // Also check if there is an associated symbol
  if ((s = (STAN_SYM*) stan_table_find (k->sym, addr)))
    {
      printf (" + Found Symbol %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- DEBUG: Symbol '%s' not found\n", name);
      return -1;
    }

  return 0;

}

int           
stan_core_rename_label_at (STAN_CORE *k, long addr, char *name)
{
  STAN_SYM *s;

  if (!k) return -1;
  if (!name) return -1;
  if (!addr) return -1;

  if ((s = (STAN_SYM*) stan_table_find (k->label, addr)))
    {
      printf (" + Found label %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- Label '%s' not found\n", name);
    }

  // Also check if there is an associated symbol
  if ((s = (STAN_SYM*) stan_table_find (k->sym, addr)))
    {
      printf (" + Found Symbol %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- DEBUG: Symbol '%s' not found\n", name);
      return -1;
    }

  return 0;
}


int           
stan_core_rename_func (STAN_CORE *k, char *name, char *name1)
{
  STAN_SYM *s;


  if (!k) return -1;
  if (!name) return -1;
  if (!name1) return -1;

  if ((s = (STAN_SYM*)stan_table_find_by_name (k->func, name)))
    {
      printf (" + Found function %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name1);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "Function '%s' not found\n", name);
    }
  // Also check if there is an associated symbol
  if ((s = (STAN_SYM*) stan_table_find_by_name (k->sym, name)))
    {
      printf (" + Found Symbol %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name1);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- DEBUG: Symbol '%s' not found\n", name);
    }

  return 0;
}


int           
stan_core_rename_label (STAN_CORE *k, char *name, char *name1)
{
  STAN_SYM *s;

  if (!k) return -1;
  if (!name) return -1;
  if (!name1) return -1;

  if ((s = (STAN_SYM*) stan_table_find_by_name (k->label, name)))
    {
      printf (" + Found label %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name1);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- Label '%s' not found\n", name);
    }

  // Also check if there is an associated symbol
  if ((s = (STAN_SYM*) stan_table_find_by_name (k->sym, name)))
    {
      printf (" + Found Symbol %s\n", name);
      if (s->id) free (s->id);
      s->id = strdup (name1);
      s->dump = 1;
    }
  else
    {
      fprintf (stderr, "- DEBUG: Symbol '%s' not found\n", name);
    }

  return 0;
}


int           
stan_core_def_func (STAN_CORE *k, char *name, long addr)
{
  STAN_SYM *s, *s1;


  if (!k) return -1;
  if (!name) return -1;

  if ((s = (STAN_SYM*) stan_table_find_by_name (k->sym, name)))
    {
      fprintf (stderr, "- Function '%s' already defined\n", name);
      return -1;
    }
  s = stan_sym_new (name, addr);
  s->dump = 1;
  stan_table_add (k->func, (STAN_ITEM*) s);
  stan_table_sort (k->func);
  s1 = stan_sym_clone (s);
  stan_table_add (k->sym, (STAN_ITEM*)s1);
  stan_table_sort (k->sym);
  return 0;
}

int           
stan_core_def_sym (STAN_CORE *k, char *name, long addr)
{
  STAN_SYM *s;


  if (!k) return -1;
  if (!name) return -1;

  if ((s = (STAN_SYM*) stan_table_find_by_name (k->sym, name)))
    {
      fprintf (stderr, "- Function '%s' already defined\n", name);
      return -1;
    }
  s = stan_sym_new (name, addr);
  s->dump = 1;
  stan_table_add (k->sym, (STAN_ITEM*) s);
  stan_table_sort (k->sym);
  return 0;
}


STAN_SEGMENT*   
stan_core_find_func_section (STAN_CORE *k, long addr)
{
  int           i, n;
  long          rel;
  STAN_SEGMENT  *sec;

  if (!k) return NULL;
  if (!addr) return  NULL;

  n = k->sec->n;
  for (i = 0; i < n; i++)
    {
      sec = (STAN_SEGMENT*) k->sec->p[i];
      rel = addr - sec->addr;

      if (rel >=0 && rel < sec->size) return sec;
    }

  return NULL;
}

int           
stan_core_add_comment (STAN_CORE *k, long addr, char *comment)
{
  STAN_COMMENT *c;
 
  if (!k) return -1;
  if (!addr) return -1;
  if (!comment) return -1;

  // Find addr in comment table
  if ((c = (STAN_COMMENT*) stan_table_find (k->comment, addr)) == NULL)
    {
      // Add comment
      c = (STAN_COMMENT*) malloc (sizeof (STAN_COMMENT));
      c->addr = addr;
      c->comment = strdup (comment);
      c->id = strdup ("NONAME"); // We do not need this
      stan_table_add (k->comment, (STAN_ITEM*)c);
      stan_table_sort (k->comment);
    }
  else
    {
      // It if exists overwrite
      if (c->comment) free (c->comment);
      c->comment = strdup (comment);
    }

  return 0;
      
}

int           
stan_core_del_comment (STAN_CORE *k, long addr)
{
  STAN_COMMENT *c;

  if (!k) return -1;
  if (!addr) return -1;

  if ((c = (STAN_COMMENT*) stan_table_find (k->comment, addr)) != NULL)
    {
      if (c->comment) free (c->comment);
      c->comment = NULL;
      // TODO: Add function to compact table and effectively remove the entry
    }
  else
    {
      fprintf (stderr, "- No comment at address %p\n", (void*)addr);
    }

  return 0;
}
STAN_SYM*     
stan_core_get_closest_symbol (STAN_CORE *k, long addr)
{
  int i,n;
  n = k->sym->n;
  for (i = 0; i < n; i++)
    if (k->sym->p[i]->addr >= addr) 
      {
	if (k->sym->p[i]->addr == addr) return k->sym->p[i];
	return (i > 0 ? k->sym->p[i -1] : k->sym->p[0]);
      }
  return NULL;
}
