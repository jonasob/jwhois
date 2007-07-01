/*
    This file is part of jwhois
    Copyright (C) 1999-2005,2007  Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
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
#include <init.h>
#include <utils.h>
#include <jconfig.h>

#include <string.h>

#define DO_HELP    0x01
#define DO_VERSION 0x02
#define DO_DISPLAY 0x04
#define DO_LIMIT   0x08
static struct option long_options[] = 
{
  {"version", 0, 0, DO_VERSION},
  {"help", 0, 0, DO_HELP},
  {"rwhois", 0, 0, 'r'},
  {"rwhois-display", 1, 0, DO_DISPLAY},
  {"rwhois-limit", 1, 0, DO_LIMIT},
  {"config", 1, 0, 'c'},
  {"host", 1, 0, 'h'},
  {"port", 1, 0, 'p'},
  {"force-lookup", 0, 0, 'f'},
  {"disable-cache", 0, 0, 'd'},
  {"no-redirect", 0, 0, 'n'},
  {"no-whoisservers", 0, 0, 's'},
  {"verbose", 0, 0, 'v'},
  {"display-redirections", 0, 0, 'i'},
  {"raw", 0, 0, 'a'},
  {0, 0, 0, 0}
};

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

/* This is set if caching is enabled */
int cache;

/* Set if checking for a cached copy of a document should be bypassed */
int forcelookup;

/* Verbose debugging output */
int verbose;

/* Host specified on the command line */
char *ghost;

/* Port specified on the command line */
int gport;

/* Name of the current configuration file */
char *config;

/* Name of the cache database */
char *cfname;

/* Default whois-servers.net domain */
char *whoisservers;

/* Default expire time for cached objects */
int cfexpire;

/* Whether or not to use lookup_redirect() on whois server output */
int redirect;

/* Set to 1 to display all redirects, otherwise display only final reply */
int display_redirections;

/* Set to 1 to send query in raw form to the host instead of mangling it
   through query-format */
int raw_query;

/* Set to 1 to force an rwhois query */
int rwhois;

/* Set to a valid display name for rwhois queries */
char *rwhois_display;

/* Set to a valid limit for rwhois queries */
int rwhois_limit;

/* Set to 0 to completely disable whois-servers.net service support */
int enable_whoisservers;

/* Timeout value for connect calls in seconds */
int connect_timeout;

void help_version(int onlyversion)
{
  char *COPYRIGHT = _("Copyright (C) 1999-%d  Free Software Foundation, Inc.\n");
  char *LICENSE =  _("This program is free software with ABSOLUTELY NO WARRANTY; you may\n\
redistribute it under the terms of the GNU General Public License.");

  printf("%s %s %s, ", PACKAGE, _("version"), VERSION);
  printf(COPYRIGHT, 2007);
  printf("%s\n\n", LICENSE);
  if (!onlyversion)
    {
      printf("%s\n", _("Usage: jwhois [OPTIONS] [QUERY]"));
      
      printf(_("  --version                  display version number and patch level\n\
  --help                     display this help\n\
  -v, --verbose              verbose debug output\n\
  -c FILE, --config=FILE     use FILE as configuration file\n\
  -h HOST, --host=HOST       explicitly query HOST\n\
  -n, --no-redirect          disable content redirection\n\
  -s, --no-whoisservers      disable whois-servers.net service support\n\
  -a, --raw                  disable reformatting of the query\n\
  -i, --display-redirections display all redirects instead of hiding them\n\
  -p PORT, --port=PORT       use port number PORT (in conjunction with HOST)\n\
  -r, --rwhois               force an rwhois query to be made\n\
  --rwhois-display=DISPLAY   sets the display option in rwhois queries\n\
  --rwhois-limit=LIMIT       sets the maximum number of matches to return\n"));

#ifndef NOCACHE
   printf(_("  -f, --force-lookup         force lookup even if the entry is cached\n\
  -d, --disable-cache        disable cache functions\n"));
#endif
   printf("\n\n%s\n", _("Report bugs to bug-jwhois@gnu.org"));
    }
}

int
parse_args(int *argc, char ***argv)
{
  int optch, option_index;
  char *ret;
  FILE *in;
  
  cache = 1;
  forcelookup = 0;
  verbose = 0;
  ghost = NULL;
  gport = 0;
  config = NULL;
  redirect = 1;
  display_redirections = 0;
  whoisservers = NULL;
  raw_query = 0;
  rwhois = 0;
  rwhois_display = NULL;
  rwhois_limit = 0;
  enable_whoisservers = 1;

  while (1)
    {
      optch = getopt_long(*argc, *argv, "rainsvfdc:h:p:", long_options, &option_index);
      if (optch == EOF)
	break;
      
      switch (optch)
	{
	case DO_VERSION:
	  help_version(1);
	  exit(0);
	case DO_HELP:
	  help_version(0);
	  exit(0);
	case 'v':
	  verbose += 1;
	  break;
	case 'f':
	  forcelookup = 1;
	  break;
	case 'd':
	  cache = 0;
	  break;
	case 'n':
	  redirect = 0;
	  break;
	case 'a':
	  raw_query = 1;
	  break;
	case 'i':
	  display_redirections = 1;
	  break;
	case 's':
	  enable_whoisservers = 0;
	  break;
	case 'r':
	  rwhois = 1;
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
	case DO_DISPLAY:
	  if (rwhois_display) free(rwhois_display);
	  rwhois_display = malloc(strlen(optarg)+1);
	  strncpy(rwhois_display, optarg, strlen(optarg)+1);
	  break;
	case DO_LIMIT:
#ifdef HAVE_STRTOL
	  rwhois_limit = strtol(optarg, &ret, 10);
	  if (*ret != '\0')
	    {
	      printf("[%s (%s)]\n",
		      _("Invalid limit"),
		      optarg);
	      break;
	    }
#else
	  rwhois_limit = atoi(optarg);
#endif
	  break;
	case 'p':
#ifdef HAVE_STRTOL
	  gport = strtol(optarg, &ret, 10);
	  if (*ret != '\0')
	    {
	      printf("[%s: %s]\n",
		      _("Invalid port number"),
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
      help_version(0);
      exit(0);
    }

  if (config)
    {
      in = fopen(config, "r");
      if (!in)
	{
	  printf("[%s: %s]\n",
		  config, _("Unable to open"));
	  exit(1);
	}
    }
  else
    {
      in = fopen(SYSCONFDIR "/jwhois.conf", "r");
      if (!in && verbose)
	printf("[%s: %s]\n",
	       SYSCONFDIR "/jwhois.conf", _("Unable to open"));
      else
	config = SYSCONFDIR "/jwhois.conf";
    }
  if (in)
    jconfig_parse_file(in);

  if (verbose>1)
    {
      printf("[Debug: Cache = %s]\n", cache?"On":"Off");
      printf("[Debug: Force lookup = %s]\n", forcelookup?"Yes":"No");
      printf("[Debug: Force host = %s]\n", ghost?ghost:"(None)");
      printf("[Debug: Force port = %s]\n", gport?(char *)create_string("%d",gport):"(None)");
      printf("[Debug: Config file name = %s]\n", config?config:"(None)");
      printf("[Debug: Follow redirections = %s]\n", redirect?"Yes":"No");
      printf("[Debug: Display redirections = %s]\n", display_redirections?"Yes":"No");
      printf("[Debug: Whois-servers.net service support = %s]\n", enable_whoisservers?"Yes":"No");
      printf("[Debug: Whois-servers domain = %s]\n", whoisservers?whoisservers:WHOISSERVERS);
      printf("[Debug: Raw query = %s]\n", raw_query?"Yes":"No");
      printf("[Debug: Rwhois display = %s]\n", rwhois_display?rwhois_display:"(None)");
      printf("[Debug: Rwhois limit = %s]\n", rwhois_limit?(char *)create_string("%d",rwhois_limit):"(None)");

      printf("[Debug: Force rwhois = %s]\n", rwhois?"Yes":"No");
    }
  return optind;
}
