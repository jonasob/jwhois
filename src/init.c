/*
    This file is part of jwhois
    Copyright (C) 1999  Jonas Öberg

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
#endif

#include <getopt.h>

#define DO_HELP    0x01
#define DO_VERSION 0x02
static struct option long_options[] = 
{
  {"version", 0, 0, DO_VERSION},
  {"help", 0, 0, DO_HELP},
  {"config", 1, 0, 'c'},
  {"host", 1, 0, 'h'},
  {"port", 1, 0, 'p'},
  {"force-lookup", 0, 0, 'f'},
  {"disable-cache", 0, 0, 'd'},
  {"verbose", 0, 0, 'v'},
  {0, 0, 0, 0}
};

int cache;
int forcelookup;
int verbose;
char *ghost;
int gport;
char *config;

char *cfname;
int cfexpire;

void help(void)
{
#ifdef WITH_CACHE
  printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", PACKAGE, " version ", VERSION,
#else
  printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s", PACKAGE, " version ", VERSION,
#endif
	 ", Copyright (C) 1999 Jonas Öberg\n",
	 "This is free software with ABSOLUTELY NO WARRANTY.\n\n",
	 "Usage: jwhois [OPTIONS] [QUERIES...]\n",
	 "  --version               display version number and patch level\n",
	 "  --help                  display this help\n",
	 "  -c FILE, --config=FILE  use FILE as configuration file\n",
	 "  -h HOST, --host=HOST    explicitly query HOST\n",
	 "  -p PORT, --port=PORT    use port number PORT (in conjunction with HOST)\n",
	 "                          query instead of concatenating then together\n",
#ifdef WITH_CACHE
	 "  -f, --force-lookup      force lookup even if the entry is cached\n",
	 "  -d, --disable-cache     disable cache functions\n",
#endif
	 "  -v, --verbose           verbose debugging output\n",
	 "\n\nReport bugs to jonas@coyote.org\n");
}

int
parse_args(argc, argv)
  int *argc;
  char ***argv;
{
  int optch, option_index;
  char *ret, *ret2;
  FILE *in;
  
  cache = 1;
  forcelookup = 0;
  verbose = 0;
  ghost = NULL;
  gport = 0;
  config = NULL;

  while (1)
    {
      optch = getopt_long(*argc, *argv, "vfdc:h:p:", long_options, &option_index);
      if (optch == EOF)
	break;
      
      switch (optch)
	{
	case DO_VERSION:
	  printf("%s %s\n", PACKAGE, VERSION);
	  exit(0);
	case DO_HELP:
	  help();
	  exit(0);
	case 'v':
	  verbose = 1;
	  break;
	case 'f':
	  forcelookup = 1;
	  break;
	case 'd':
	  cache = 0;
	  break;
	case 'c':
	  if (config) free(config);
	  config = malloc(strlen(optarg)+1);
	  strncpy(config, optarg, strlen(optarg)+1);
	  break;
	case 'h':
	  if (ghost) free(ghost);
	  ghost = malloc(strlen(optarg)+1);
	  strncpy(ghost, optarg, strlen(optarg)+1);
	  break;
	case 'p':
#ifdef HAVE_STRTOL
	  gport = strtol(optarg, &ret, 10);
	  if (*ret != '\0')
	    {
	      printf("[%s (%s)]\n",
		      "Invalid port number",
		      optarg);
	      break;
	    }
#else
	  gport = atoi(optarg);
#endif
	  break;
	}
    }

  if (optind == *argc)
    {
      help();
      exit(0);
    }

  if (config)
    {
      in = fopen(config, "r");
      if (!in)
	{
	  printf("[Unable to open %s]\n",
		  config);
	  exit(1);
	}
    }
  else
    {
      in = fopen(SYSCONFDIR "/jwhois.conf", "r");
      if (!in)
	{
	  in = fopen(DATADIR "/jwhois.conf", "r");
	}
    }
  if (in)
    parse_config(in);
  else
    if (verbose)
      printf("[%s]\n",
	      "No configuration file found -- using defaults");

  return optind;
}
