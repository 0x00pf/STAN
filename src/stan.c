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

static char *cmd[] = {
  "case.dump",
  "case.save",
  "case.load",
  "core.info",
  "core.symbols",
  "core.functions",
  "core.labels",
  "core.load",
  "core.ana",
  "cfg.dump",
  "cfg.get",
  "cfg.set",
  "dis.section",
  "dis.function",
  "dis.addr",
  "func.rename",
  "label.rename",
  "comment.add",
  "comment.del",
  "mem.dump",
  "mem.poke",
  "func.def",
  "sym.def",
  "help.abi",
  "quit",
  NULL
};

typedef void* (*CMD_FUNC)(STAN_CASE *, char *pars);

int
run_cmd (STAN_CASE *c, char *buffer1)
{
  char *buffer = strdup (buffer1);
  int i = strlen(buffer);

  while (buffer[i - 1] == ' ') i--;
  buffer[i] = 0;

  if (!buffer) return 0;
  if (!strncasecmp (buffer, "case.dump", strlen ("case.dump")))
    {
      stan_case_dump (c);
    }
  else if (!strncasecmp (buffer, "case.load", strlen ("case.load")))
    {
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
      stan_core_clean (c->k);
      stan_core_load (c->k, buffer + strlen ("core.load "));
      stan_core_identify (c->k);
      stan_ana_init (c->k);
    }
  else if (!strncasecmp (buffer, "dis.section", strlen ("dis.section")))
    {
      stan_dis_section (c->k, buffer + strlen ("dis.section "));
    }
  else if (!strncasecmp (buffer, "dis.function", strlen ("dis.function")))
    {
      stan_dis_func (c->k, buffer + strlen ("dis.function "));
    }
  else if (!strncasecmp (buffer, "dis.addr", strlen ("dis.addr")))
    {
      long addr;
      int  count;
      sscanf (buffer + strlen ("dis.addr "), "%p %d", &addr, &count);
      stan_dis_addr (c->k, addr, count);
    }

  else if (!strncasecmp (buffer, "cfg.dump", strlen ("cfg.dump")))
    {
      stan_cfg_dump ();
    }
  else if (!strncasecmp (buffer, "cfg.get", strlen ("cfg.get")))
    {
      printf ("%s\n", stan_cfg_get (buffer + strlen ("cfg.get ")));
    }
  else if (!strncasecmp (buffer, "cfg.set", strlen ("cfg.set")))
    {
      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
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

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("func.rename ");
      sscanf (aux, "%s %s", name1, name2);
      stan_core_rename_func (c->k, name1, name2);
    }
  else if (!strncasecmp (buffer, "label.rename", strlen ("label.rename")))
    {
      char name1[1024];
      char name2[1024];

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("label.rename ");
      sscanf (aux, "%s %s", name1, name2);
      stan_core_rename_label (c->k, name1, name2);
    }

  else if (!strncasecmp (buffer, "func.def", strlen ("func.def")))
    {
      char name1[1024];
      long addr;    // XXX: Maybe we should make all address void * ??

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("func.def ");
      sscanf (aux, "%s %p", name1, (void**)&addr);
      printf ("+ Defining new funcion '%s'@%p\n", name1, (void*)addr);
      stan_core_def_func (c->k, name1, addr);
    }
  else if (!strncasecmp (buffer, "sym.def", strlen ("sym.def")))
    {
      char name1[1024];
      long addr;    // XXX: Maybe we should make all address void * ??

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("sym.def ");
      sscanf (aux, "%s %p", name1, (void**)&addr);
      printf ("+ Defining new symbol '%s'@%p\n", name1, (void*)addr);
      stan_core_def_sym (c->k, name1, addr);
    }

  else if (!strncasecmp (buffer, "comment.add", strlen ("comment.add")))
    {
      long addr;
      char *comment;

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("comment.add ");
      sscanf (aux, "%p", (void**)&addr);
      if ((comment = strchr (aux + 1, ' ')) == NULL)
	{
	  fprintf (stderr, "- Malformed command: comment hex_address comment\n");
	  return -1;
	}
      comment++;
      printf ("+ Adding comment '%s' at %p\n", comment, (void*) addr);
      stan_core_add_comment (c->k, addr, comment);
    }
  else if (!strncasecmp (buffer, "comment.del", strlen ("comment.del")))
    {
      long addr;

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("comment.del ");
      sscanf (aux, "%p", (void**)&addr);
      printf ("+ deleting comment at %p\n", (void *)addr);
      stan_core_del_comment (c->k, addr);
    }
  else if (!strncasecmp (buffer, "mem.dump", strlen ("mem.dump")))
    {
      char fmt[1024];
      long addr;
      long len;
      int  narg;

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("mem.dump ");
      if ((narg = sscanf (aux, "%s %p %ld", fmt, (void**) &addr, &len)) != 3)
	{
	  fprintf (stderr, "Invalid number of parameters\n");
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

      // FIXME:... what can I say... I'm feeling lazy
      //       Just minimal functionality  
      char *aux= buffer + strlen ("mem.poke ");
      if ((narg = sscanf (aux, "%s %p %s", fmt, (void**) &addr, str)) != 3)
	{
	  fprintf (stderr, "Invalid number of parameters\n");
	  return 0;
	}
      stan_dis_poke_block (c->k, fmt, addr, str);
    }
  else if (!strncasecmp (buffer, "case.save", strlen ("case.save")) || 
	   !strncasecmp (buffer, ":w", strlen (":w"))
	   )
    {
      stan_case_save (c, buffer + strlen ("case.save "));
    }

  else if (!strncasecmp (buffer, "quit", strlen ("quit")) || 
	   (buffer[0] == 'q' && buffer[1] == 0))
    {
      return 1;
    }



  return 0;
}


// https://robots.thoughtbot.com/tab-completion-in-gnu-readline
// http://web.mit.edu/gnu/doc/html/rlman_2.html
char **
cmd_completion(const char *text, int start, int end);
char *
cmd_generator(const char *text, int state);

char **
cmd_completion(const char *text, int start, int end)
{
  char **matches;

  matches = (char **)NULL;
  
  if (start == 0)
    matches = (char **) rl_completion_matches (text, cmd_generator);
    //matches = (char **) completion_matches (text, cmd_generator);


  return matches;
      
}

char *
cmd_generator(const char *text, int state)
{
    static int list_index, len;
    char *name;

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    while ((name = cmd[list_index++])) {
        if (strncmp(name, text, len) == 0) {
            return strdup(name);
        }
    }
    return NULL;
}


int
main (int argc, char *argv[])
{
  STAN_CASE *c;
  STAN_CORE *k;


  printf ("STAN is a sTAtic aNalyser. v 0.1\n");
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
  char *input;
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
