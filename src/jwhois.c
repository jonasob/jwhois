/*
    This file is part of jwhois
    Copyright (C) 1999  Free Software Foundation, Inc.

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

#ifdef HAVE_LIBINTL_H
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

/*
 *  This function creates a connection to the indicated host/port and
 *  returns a file descriptor or -1 if error.
 */
int
make_connect(host, port)
     char *host;
     int port;
{
  int sockfd, error;
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints, *res;
  struct sockaddr *sa;
#else
  struct sockaddr_in remote;
#endif

#ifndef HAVE_GETADDRINFO
  error = lookup_host_saddr(&remote, host, port);
  if (error < 0)
    return -1;

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (!sockfd)
    {
      return -1;
    }

  error = connect(sockfd, (struct sockaddr *)&remote, sizeof(struct sockaddr));
  if (error < 0)
    {
      return -1;
    }

#else /* HAVE_GETADDRINFO */

  error = lookup_host_addrinfo(&res, host, port);
  if (error < 0)
    {
      return -1;
    }
  while (res)
    {
      sa = res->ai_addr;
      sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
      if (sockfd == -1 && res->ai_family == PF_INET6 && res->ai_next)
        {
          /* Operating system seems to lack IPv6 support, try next entry */
          res = res->ai_next;
          continue;
        }
      if (sockfd == -1)
	{
	  printf("[%s]\n", _("error creating socket"));
	  return -1;
	}
      error = connect(sockfd, res->ai_addr, res->ai_addrlen);
      if (error >= 0)
	break;
      res = res->ai_next;
    }
  if (verbose) printf("[Debug: connect() = %d]\n", error);
  if (error < 0) return -1;
#endif
  return sockfd;
}

/*
 *  This function takes a string gotten from the commandline, splits
 *  out a hostname if one is found after an '@' sign which is not escaped
 *  by '\'.  Returns 1 is successful, else 0. qstrins is reformatted
 *  to hold only the query without hostname.
 */
int
split_host_from_query(qstring, host)
     char *qstring;
     char **host;
{
  char *tmpptr;

  tmpptr = (char *)strchr(qstring, '@');
  if (!tmpptr)
    return 0;

  tmpptr--;
  if (*tmpptr == '\\')
    return 0;
  tmpptr++;
  *tmpptr = '\0';
  tmpptr++;
  *host = tmpptr;
  return 1;
}

int
main(argc, argv)
     int argc;
     char **argv;
{
  int optind, count = 0, port = 0, ret, sockfd;
  char *qstring = NULL, *host, *text;

#ifdef HAVE_LIBINTL_H
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);
#endif

  re_syntax_options = RE_SYNTAX_EMACS;
  optind = parse_args(&argc, &argv);
  cache_init();

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

  if (verbose)
    printf("[Debug: qstring = \"%s\"]\n", qstring);

  if (ghost)
    {
      if (verbose) printf("[Debug: Calling %s:%d directly]\n", ghost, gport);
      forcelookup = 1;
      host = ghost;
      port = gport;
    }
  else if (split_host_from_query(qstring, &host))
    {
      if (verbose) printf("[Debug: Calling %s directly]\n", host);
    }
  else
    {
      ret = lookup_host(qstring, NULL, &host, &port);
      if (ret < 0)
	{
	  printf("[%s]\n", _("fatal error searching for host to query"));
	  exit(1);
	}
    }

#ifndef NOCACHE
  if (!forcelookup && cache) {
    if (verbose) printf("[Debug: Looking up entry in cache]\n");
    ret = cache_read(qstring, &text);
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

  printf("[%s]\n", host);
  while (1)
    {
      sockfd = make_connect(host, port);
      if (sockfd < 0)
	{
	  exit(1);
	}
      write(sockfd, qstring, strlen(qstring));
      write(sockfd, "\r\n", 2);
      if (verbose) printf("[Debug: Reading via fdread from file descriptor %d]\n",sockfd);
      ret = fdread(sockfd, &text);
      if (ret < 0)
	{
	  printf("[%s %s:%d]\n", _("error reading data from"), host, port);
	  exit(1);
	}
      if (redirect)
        {
          ret = lookup_redirect(host, NULL, text, &host, &port);
          if ((ret < 0) || (ret == 0)) break;
        }
      else
        {
          break;
        }
    }
      
#ifndef NOCACHE
  if (cache) {
    if (verbose) printf("[Debug: Storing in cache]\n");
    ret = cache_store(qstring, text);
    if (ret < 0)
      {
	printf("[%s]\n", _("error writing to cache"));
      }
  }
#endif

  if (verbose) printf("[Debug: Searching for %s\n", qstring);
  printf("%s", text);
  exit(0);
}
