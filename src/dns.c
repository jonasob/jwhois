/*
    This file is part of jwhois
    Copyright (C) 1999-2002,2007  Free Software Foundation, Inc.

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

#include <jwhois.h>
#include <dns.h>
#if defined(HAVE_GETADDRINFO) && !defined(HAVE_GAI_STRERROR)
#include <gai_strerror.h>
#endif

#include <string.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

#ifndef HAVE_GETADDRINFO
/*
 *  This function looks up a hostname or IP number and enters the information
 *  in a sockaddr_in structure.
 *
 *  Returns: -1  Host not found
 *           0   Success
 */
int
lookup_host_saddr(struct sockaddr_in *res, const char *host, int port)
{
  int ret;
  struct hostent *hostent;
  struct servent *sp;

  res->sin_family = AF_INET;

  if (!port) {
    if ((sp = getservbyname("whois", "tcp")) == NULL)
      res->sin_port = htons(IPPORT_WHOIS);
    else
      res->sin_port = sp->s_port;
  } else {
     res->sin_port = htons(port);
  }

#ifdef HAVE_INET_ATON
  ret = inet_aton(host, &res->sin_addr.s_addr);
#else
  res->sin_addr.s_addr = inet_addr(host);
  if (res->sin_addr.s_addr == -1)
    ret = 0;
#endif
  if (!ret)
    {
      hostent = gethostbyname(host);
      if (!hostent)
	{
	  printf("[%s: %s]\n", host, _("host not found"));
	  return -1;
	}
      memcpy(&res->sin_addr.s_addr, hostent->h_addr_list[0],
	     sizeof(res->sin_addr.s_addr));
    }
  return 0;
}
#endif


#ifdef HAVE_GETADDRINFO
/*
 *  This function looks up a hostname or IP number using the newer
 *  getaddrinfo() system call.
 *
 *  Returns:   !0   Error code (see gai_strerror())
 *             0    Success
 */
int
lookup_host_addrinfo(struct addrinfo **res, const char *host, int port)
{
  struct addrinfo hints;
  char ascport[10] = "whois";
  int error;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;

  hints.ai_socktype = SOCK_STREAM;
  if (port)
    sprintf(ascport, "%9.9d", port);

  error = getaddrinfo(host, ascport, &hints, res);

  if (error)
    {
      printf("[%s: %s]\n", host, gai_strerror(error));
      return error;
    }
  return 0;
}
#endif
