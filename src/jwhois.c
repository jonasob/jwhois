/*
    This file is part of jwhois
    Copyright (C) 1999,2001  Free Software Foundation, Inc.

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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <jconfig.h>
#include <jwhois.h>
#include <regex.h>
#include <whois.h>
#include <http.h>

#ifdef HAVE_LIBINTL_H
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

int
main(argc, argv)
     int argc;
     char **argv;
{
  int optind, count = 0, port = 0, ret;
  char *qstring = NULL, *host, *text, *tmp, *tmp2;
  struct s_whois_query wq;

#ifdef HAVE_LIBINTL_H
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  re_syntax_options = RE_SYNTAX_EMACS;
  wq.host = NULL;
  wq.port = 0;
  wq.query = NULL;
  wq.domain = NULL;

  /* Parse command line arguments and initialize the cache */
  optind = parse_args(&argc, &argv);
  cache_init();

  /* Parse remaining arguments and place them into the wq
     structure. */
  while (optind < argc)
    {
      count += strlen(argv[optind])+1;
      if (!qstring)
	qstring = malloc(count+1);
      else
	qstring = realloc(qstring, count+1);
      if (!qstring)
        {
          printf("[%s]\n", _("error allocating memory"));
          exit(1);
        }
      memcpy(qstring+count-strlen(argv[optind])-1,
	     argv[optind],
	     strlen(argv[optind])+1);
      strcat(qstring, " ");
      optind++;
    }
  qstring[strlen(qstring)-1] = '\0';
  wq.query = qstring;

  if (verbose)
    printf("[Debug: Raw query string = \"%s\"]\n", wq.query);

  if (ghost)
    {
      if (verbose) printf("[Debug: Calling %s:%d directly]\n", ghost, gport);
      wq.host = ghost;
      wq.port = gport;
    }
  else if (split_host_from_query(&wq))
    {
      if (verbose) printf("[Debug: Calling %s directly]\n", wq.host);
    }
  else
    {
      ret = lookup_host(&wq, NULL);
      if (ret < 0)
	{
	  printf("[%s]\n", _("fatal error searching for host to query"));
	  exit(1);
	}
    }

#ifndef NOCACHE
  if (!forcelookup && cache) {
    if (verbose) printf("[Debug: Looking up entry in cache]\n");
    ret = cache_read(wq.query, &text);
    if (ret < 0)
      {
	printf("[%s]\n", _("error reading cache"));
	exit(1);
      }
    else if (ret > 0)
      {
	printf("[%s]\n%s", _("cached"), text);
	exit(0);
      }
  }
#endif

  tmp = (char *)get_whois_server_option(wq.host, "rwhois");
  tmp2 = (char *)get_whois_server_option(wq.host, "http");

  if (tmp2 && 0 == strcmp(tmp2, "true"))
    ret = http_query(&wq, &text);
  else if ( (!tmp || (strncmp(tmp, "true", 4) == 0)) && (!rwhois) )
    ret = whois_query(&wq, &text);
  else
    ret = rwhois_query(&wq, &text);

  if (ret < 0)
    {
      exit(1);
    }

#ifndef NOCACHE
  if (cache) {
    if (verbose) printf("[Debug: Storing in cache]\n");
    ret = cache_store(wq.query, text);
    if (ret < 0)
      {
	printf("[%s]\n", _("error writing to cache"));
      }
  }
#endif

  printf("%s", text);
  exit(0);
}
