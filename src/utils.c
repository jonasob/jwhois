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
# include <stdarg.h>
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

#include <regex.h>
#include <jwhois.h>
#include <jconfig.h>

#ifdef HAVE_LIBINTL_H
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

char *create_string(const char *fmt, ...);

/*
 *  This creates a string.  Text book example :-)
 */
char *
create_string(const char *fmt, ...)
{
  int n, size = 100;
  char *p;
  va_list ap;

  if ((p = malloc(size)) == NULL)
    return NULL;

  while (1) {
    va_start(ap, fmt);
    n = vsnprintf(p, size, fmt, ap);
    va_end(ap);
    if (n > -1 && n < size)
      return p;
    if (n > -1)
      size = n+1;
    else
      size *= 2;
    if ((p = realloc(p, size)) == NULL)
      return NULL;
  }
}

/*
 *  This adds text to a buffer.
 */
int
add_text_to_buffer(buffer, text)
     char **buffer;
     char *text;
{
  if (!*buffer)
    {
      *buffer = malloc(strlen(text)+1);
      if (!*buffer)
	{
	  fprintf(stderr, "Can not allocate %d bytes of memory\n", strlen(*buffer)+strlen(text)+1);
	  exit(1);
	}
      strncpy(*buffer, text, strlen(text)+1);
    }
  else
    {
      *buffer = realloc(*buffer, strlen(*buffer)+strlen(text)+1);
      if (!*buffer)
	{
	  fprintf(stderr, "Can not allocate %d bytes of memory\n", strlen(*buffer)+strlen(text)+1);
	  exit(1);
	}
      strncat(*buffer, text, strlen(text)+1);
    }
  return 0;
}

/*
 *  This will search the jwhois.server-options base in the configuration
 *  file and return the base domain value for the given hostname.
 */
char *
get_whois_server_domain_path(hostname)
     char *hostname;
{
  struct jconfig *j;
  struct re_pattern_buffer      rpb;
  char *error, *base;
  int ind, i;
  char case_fold[256];

  for (i = 0; i < 256; i++)
    case_fold[i] = toupper(i);

  jconfig_set();
  while (j = jconfig_next_all("jwhois.server-options"))
    {
      rpb.allocated = 0;
      rpb.buffer = (unsigned char *)NULL;
      rpb.translate = case_fold;
      rpb.fastmap = (char *)NULL;
      if (error = (char *)re_compile_pattern(j->domain+22,
					     strlen(j->domain+22), &rpb))
	{
	  return NULL;
	}
      ind = re_search(&rpb, hostname, strlen(hostname), 0, 0, NULL);
      if (ind == 0)
	{
	  return j->domain;
	}
      else if (ind == -2)
	{
	  return NULL;
	}
    }
  return NULL;
  jconfig_end();
}

/*
 *  This will search the jwhois.server-options base in the configuration
 *  file and return the value of the key corresponding to the given hostname.
 */
char *
get_whois_server_option(hostname, key)
     char *hostname;
     char *key;
{
  struct jconfig *j;
  char *base;
  base = get_whois_server_domain_path(hostname);

  if (!base)
    return NULL;
  
  jconfig_set();
  j = jconfig_getone(base, key);
  if (!j)
    return NULL;

  return j->value;
}

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

