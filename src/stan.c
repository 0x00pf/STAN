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

#include <readline/readline.h>
#include <readline/history.h>

#include "case.h"
#include "dis.h"
#include "cfg.h"
#include "ana.h"
#include "utils.h"
#include "symb.h"

#include "../config.h"

static  STAN_CASE *c = NULL;
static  STAN_CORE *k = NULL;


typedef struct stan_cmd_t
{
  char *id;
  char *help;
} STAN_CMD;


static STAN_CMD cmd[] = {
  {"case.dump", "Dumps current case information\n"},
  {"case.save", "Saves current case. File used is corename.srep\n"},
  {"case.load", "Loads a previously saved case. Ex: case.load filename.srep\n"},
  {"core.info", "Shows core info\n"},
  {"core.symbols", "Shows identified core symbols\n"},
  {"core.functions", "Shows identified core functions\n"},
  {"core.labels", "Shows identified core labels\n"},
  {"core.load", "Loads a core (binary) and analyses it. Ex: core.load binary\n"},
  {"core.save", "Saves current core image. Automatically stores a case file. If no filename is provided the orignal name + .PATCHED is used. Ex: core.save binary.patch\n"},
  {"core.ana", "Not yet implemented\n"},
  {"cfg.dump", "Shows current STAN configuration\n"},
  {"cfg.get", "Gets a configuration value. Ex: cfg.get cfg_val\n"},
  {"cfg.set", "Sets a configuration value.Ex: cfg.set cfg_val val\n"},
  {"dis.section", "Disassembles the specified section. Ex: dis.section section_name\n"},
  {"dis.function", "Disassembles the specified function. Ex: dis.function function_name\n"},
  {"dis.addr", "Disassembles the indicated number of instruction starting from the specified address.Ex: dis.add addr count\n"},
  {"func.rename", "Renames a function. Ex: func.rename old_name new_name\n"},
  {"label.rename", "Renames a label. Ex: label.rename old_name new_name\n"},
  {"label.gen_table", "Generates labels for memory table. Ex: label.gen_table prefix addr count\n"},
  {"comment.add", "Adds a comment to the specified addres. Ex: comment.add addr coment\n"},
  {"comment.del", "Deleted a comment at the specified addres. Ex: comment.del addr\n"},
  {"mem.dump", "Dumps memory. Ex: mem.dump [x|p] addr count.\n\t\t   fmt = x : dumps hex bytes\n\t\t   fmt = p : dumps pointers\n"},
  {"mem.poke", "Writes to memory.Ex:   mem.poke [x|p] addr value.\n\t\t   fmt = x : writes hex string\n\t\t   fmt = p : Writes pointer\n"},
  {"mem.xor", "Xors memory with a key.Ex:   mem.xor key addr1 addr2\n"},
  {"func.def", "Defines a function at the specified address. Ex: func.def function_name addr\n"},
  {"sym.def", "Defines a symbol at the specified address. Ex: sym.def symbol_name addr\n"},
  {"help.abi", "Shows current ABI for the loaded core\n"},
  {"help", "Shows command help\n"},
  {"quit", "By STAN\n"},
   {NULL, NULL}
};

typedef void* (*CMD_FUNC)(STAN_CASE *, char *pars);

static
int 
_find_cmd (char *c)
{
  int i;
  for (i = 0; cmd[i].id; i++)
    if (!strncmp (c, cmd[i].id, strlen(cmd[i].id))) return i;
  return -1;
}

int
run_cmd (STAN_CASE *c, char *buffer1)
{
  char *buffer = strdup (buffer1);
  int   cmd_indx;
  int   i = strlen(buffer);

  while (buffer[i - 1] == ' ') i--;
  buffer[i] = 0;

  if (buffer[0] == '!') 
    {
      system (buffer + 1);
      return 0;
    }

  cmd_indx = _find_cmd (buffer);
  if (i > 2 && cmd_indx < 0) 
    {
      fprintf (stderr, "- Unknown command '%s'\n", buffer);
      return 0;
    }

  if (!buffer) return 0;
  if (!strncasecmp (buffer, "case.dump", strlen ("case.dump")))
    {
      stan_case_dump (c);
    }
  else if (!strncasecmp (buffer, "case.load", strlen ("case.load")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      stan_case_free (c);
      c = stan_case_load (c, buffer + strlen ("case.load "));
    }

  else if (!strncasecmp (buffer, "help.abi", strlen ("help.abi")))
    {
      printf ("  Current Core is: %s %s %s\n",
	      stan_core_get_os_name(c->k),
	      stan_core_get_arch_name(c->k),
	      stan_core_get_mode_name(c->k));
      if (c->k->os == STAN_CORE_OS_LINUX)
	{
	  switch (c->k->arch)
	    {
	    case STAN_CORE_ARCH_X86:
	      {
		if (c->k->mode == STAN_CORE_MODE_32)
		  printf ("  -> func ((ESP + 1), (ESP + 2),...) -> EAX\n");
		else
		  printf ("  -> func (RDI, RSI, RDX, RCX) -> RAX\n");
		break;
	      }
	    case STAN_CORE_ARCH_ARM:
	      {
		if (c->k->mode == STAN_CORE_MODE_ARM)
		  printf ("  ->func (r0, r1, r2, r3) -> r0\n");
		break;
	      }
	    default:
	      {
		printf ("- Unknown architecture\n");
	      }
	    }
	}
      else
	{
	  printf ("- Unknown OS... cannot guess ABI\n");
	}
    }

  else if (!strncasecmp (buffer, "core.info", strlen ("core.info")))
    {
      stan_core_dump (c->k);
    }
  else if (!strncasecmp (buffer, "core.ana", strlen ("core.ana")))
    {
      printf ("- Command not implemented yet\n");
    }

  else if (!strncasecmp (buffer, "core.symbols", strlen ("core.symbols")))
    {

      stan_core_dump_symbols (c->k);
    }
  else if (!strncasecmp (buffer, "core.functions", strlen ("core.functions")))
    {
      printf ("Dumping Functions\n");
      stan_core_dump_func (c->k);
    }
  else if (!strncasecmp (buffer, "core.labels", strlen ("core.labels")))
    {
      printf ("Dumping Labels\n");
      stan_core_dump_label (c->k);
    }

  else if (!strncasecmp (buffer, "core.load", strlen ("core.load")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_core_clean (c->k);
      stan_core_load (c->k, buffer + strlen ("core.load "));
      stan_core_identify (c->k);
      stan_ana_init (c->k);
    }
  else if (!strncasecmp (buffer, "core.save", strlen ("core.save")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  // No parameter... let STAN chose a name
	  stan_core_save (c->k, NULL);
	}
      else
	stan_core_save (c->k, buffer + strlen ("core.save "));

      stan_case_save (c, buffer + strlen ("core.save "), 0);
    }

  else if (!strncasecmp (buffer, "dis.section", strlen ("dis.section")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_dis_section (c->k, buffer + strlen ("dis.section "));
    }
  else if (!strncasecmp (buffer, "dis.function", strlen ("dis.function")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_dis_func (c->k, buffer + strlen ("dis.function "));
    }
  else if (!strncasecmp (buffer, "dis.addr", strlen ("dis.addr")))
    {
      long addr;
      int  count, nargs;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      nargs = sscanf (buffer + strlen ("dis.addr "), "%p %d", (void**)&addr, &count);
      if (nargs != 2)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_dis_addr (c->k, addr, count);
    }

  else if (!strncasecmp (buffer, "cfg.dump", strlen ("cfg.dump")))
    {
      stan_cfg_dump ();
    }
  else if (!strncasecmp (buffer, "cfg.get", strlen ("cfg.get")))
    {
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      printf ("%s\n", stan_cfg_get (buffer + strlen ("cfg.get ")));
    }
  else if (!strncasecmp (buffer, "cfg.set", strlen ("cfg.set")))
    {
      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      char *aux= buffer + strlen ("cfg.set ");
      char *val = strchr (aux,  ' ');
      *val = 0;
      val ++;
      stan_cfg_set (aux, val);
    }
  else if (!strncasecmp (buffer, "func.rename", strlen ("func.rename")))
    {
      char name1[1024];
      char name2[1024];
      int  nargs;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("func.rename ");
      nargs = sscanf (aux, "%s %s", name1, name2);
      if (nargs != 2)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_core_rename_func (c->k, name1, name2);
    }
  else if (!strncasecmp (buffer, "label.rename", strlen ("label.rename")))
    {
      char name1[1024];
      char name2[1024];
      int  nargs;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("label.rename ");
      nargs = sscanf (aux, "%s %s", name1, name2);
      if (nargs != 2)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      stan_core_rename_label (c->k, name1, name2);
    }

  else if (!strncasecmp (buffer, "func.def", strlen ("func.def")))
    {
      char name1[1024];
      long addr;    // XXX: Maybe we should make all address void * ??
      int  nargs;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}


      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("func.def ");
      nargs = sscanf (aux, "%s %p", name1, (void**)&addr);
      if (nargs != 2)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      printf ("+ Defining new funcion '%s'@%p\n", name1, (void*)addr);
      stan_core_def_func (c->k, name1, addr);
    }
  else if (!strncasecmp (buffer, "sym.def", strlen ("sym.def")))
    {
      char name1[1024];
      long addr;    // XXX: Maybe we should make all address void * ??
      int  nargs;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("sym.def ");
      nargs = sscanf (aux, "%s %p", name1, (void**)&addr);
      if (nargs != 2)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      printf ("+ Defining new symbol '%s'@%p\n", name1, (void*)addr);
      stan_core_def_sym (c->k, name1, addr);
    }

  else if (!strncasecmp (buffer, "comment.add", strlen ("comment.add")))
    {
      long addr;
      char *comment;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("comment.add ");
      if (sscanf (aux, "%p", (void**)&addr) == 0)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      if ((comment = strchr (aux + 1, ' ')) == NULL)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      comment++;
      printf ("+ Adding comment '%s' at %p\n", comment, (void*) addr);
      stan_core_add_comment (c->k, addr, comment);
    }
  else if (!strncasecmp (buffer, "comment.del", strlen ("comment.del")))
    {
      long addr;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}


      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("comment.del ");
      if ((sscanf (aux, "%p", (void**)&addr)) == 0)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      printf ("+ deleting comment at %p\n", (void *)addr);
      stan_core_del_comment (c->k, addr);
    }
  else if (!strncasecmp (buffer, "label.gen_table", strlen ("label.gen_table")))
    {
      char fmt[1024];
      long addr;
      long len;
      int  narg;

      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("label.gen_table ");
      if ((narg = sscanf (aux, "%s %p %ld", fmt, (void**) &addr, &len)) != 3)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      stan_dis_generate_labels (c->k, fmt, addr, len);
    }

  else if (!strncasecmp (buffer, "mem.dump", strlen ("mem.dump")))
    {
      char fmt[1024];
      long addr;
      long len;
      int  narg;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("mem.dump ");
      if ((narg = sscanf (aux, "%s %p %ld", fmt, (void**) &addr, &len)) != 3)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      stan_dis_dump_block (c->k, fmt, addr, len);
    }
  else if (!strncasecmp (buffer, "mem.poke", strlen ("mem.poke")))
    {
      char fmt[1024];
      char str[1024];
      long addr;
      int  narg;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("mem.poke ");
      if ((narg = sscanf (aux, "%s %p %s", fmt, (void**) &addr, str)) != 3)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      stan_dis_poke_block (c->k, fmt, addr, str);
    }
  else if (!strncasecmp (buffer, "mem.xor", strlen ("mem.xor")))
    {
      char fmt[1024];
      char str[1024];
      long addr, addr1;
      int  narg;
      if (strlen(buffer) == strlen(cmd[cmd_indx].id))
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("mem.xor ");
      if ((narg = sscanf (aux, "%s %p %p", str, (void**) &addr, (void**)  &addr1)) != 3)
	{
	  printf ("\t%s", cmd[cmd_indx].help);
	  return 0;
	}
      stan_mem_xor (c->k, str, addr, addr1);
    }

  else if (!strncasecmp (buffer, "help", strlen ("help")))
    {
      int i;
      for (i = 0; cmd[i].id;  i++)
	{
	  if (strlen (cmd[i].id) < 8) 
	      printf ("%s\t\t: %s", cmd[i].id, cmd[i].help);
	  else
	      printf ("%s\t: %s", cmd[i].id, cmd[i].help);
	}
    }

  else if (!strncasecmp (buffer, "case.save", strlen ("case.save")) || 
	   !strncasecmp (buffer, ":w", strlen (":w"))
	   )
    {
      stan_case_save (c, buffer + strlen ("case.save "), 1);
    }

  else if (!strncasecmp (buffer, "quit", strlen ("quit")) || 
	   (buffer[0] == 'q' && buffer[1] == 0))
    {
      return 1;
    }
  else
    {
      fprintf (stderr, "- Unknown command '%s'\n", buffer);
      return 0;
    }



  return 0;
}

char **cmd_completion(const char *text, int start, int end);
char *cmd_generator(const char *text, int state);
char *func_generator(const char *text, int state);
char *label_generator(const char *text, int state);
char *section_generator(const char *text, int state);

char **
cmd_completion(const char *text, int start, int end)
{
  char **matches;
  char *current = rl_line_buffer;

  matches = (char **)NULL;
  
  if (start == 0)
    matches = (char **) rl_completion_matches (text, cmd_generator);
  else if (!strncmp (current, "dis.function ", strlen ("dis.function ")) ||
	   !strncmp (current, "func.rename ", strlen ("func.rename "))
	   )
    {
      matches = (char **) rl_completion_matches (text, func_generator);
    }
  else if (!strncmp (current, "label.rename ", strlen ("label.rename ")))
    {
      matches = (char **) rl_completion_matches (text, label_generator);
    }
  else if (!strncmp (current, "dis.section ", strlen ("dis.section ")))
    {
      matches = (char **) rl_completion_matches (text, section_generator);
    }

  return matches;     
}


char *
func_generator(const char *text, int state)
{
  static int list_index, list_index1, len;
  char *name;
  
  if (!state) 
    {
      list_index = 0;
      list_index1 = 0;
      len = strlen(text);
    }
  
  
  while ((list_index < k->func->n)) 
    {   
      name = k->func->p[list_index++]->name;
      if (strncmp(name, text, len) == 0) 
	{
	  return strdup(name);
	}
    }

  while ((list_index1 < k->sym->n)) 
    {   
      name = k->sym->p[list_index1++]->name;
      if (strncmp(name, text, len) == 0) 
	{
	  return strdup(name);
	}
    }
  
  return NULL;
}

char *
label_generator(const char *text, int state)
{
  static int list_index, len;
  char *name;
  
  if (!state) 
    {
      list_index = 0;
      len = strlen(text);
    }
  
  
  while ((list_index < k->label->n)) 
    {   
      name = k->label->p[list_index++]->name;
      if (strncmp(name, text, len) == 0) 
	{
	  return strdup(name);
	}
    }
  
  return NULL;
}

char *
section_generator(const char *text, int state)
{
  static int list_index, len;
  char *name;
  
  if (!state) 
    {
      list_index = 0;
      len = strlen(text);
    }
  
  
  while ((list_index < k->sec->n)) 
    {   
      name = k->sec->p[list_index++]->name;
      if (strncmp(name, text, len) == 0) 
	{
	  return strdup(name);
	}
    }
  
  return NULL;
}


char *
cmd_generator(const char *text, int state)
{
  static int list_index, len;
  char *name;
  
  if (!state) 
    {
      list_index = 0;
      len = strlen(text);
    }
  

  while ((name = cmd[list_index++].id)) {   
    if (strncmp(name, text, len) == 0) {
      return strdup(name);
    }

  }
  
    return NULL;
}


int
main (int argc, char *argv[])
{


  printf ("STAN is a sTAtic aNalyser. v " VERSION "\n");
  printf ("(c) pico\n\n");
  // TODO: Command-line args processing

  stan_cfg_init ();
  // Code using case
  c = stan_case_new (NULL);

  // Code using just core
  k = stan_core_new ();
  stan_case_set_core (c, k);
  if (argc > 1)
    {
      stan_core_load (k, argv[1]);
      stan_core_identify (k);
      stan_ana_init (k);
      stan_case_dump (c);
    }

  int flag = 0;
  char *input = NULL;
  rl_attempted_completion_function = cmd_completion;
  while (!flag)
    {
      input = readline ("STAN] > ");
      add_history(input);

      flag = run_cmd (c, input);
      free (input);
    }

  return 0;
}
