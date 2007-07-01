/*
    This file is part of jwhois
    Copyright (C) 2001-2002,2007  Free Software Foundation, Inc.

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
# include <stdarg.h>
#endif

#include <regex.h>
#include <jwhois.h>
#include <jconfig.h>
#include <whois.h>
#include <lookup.h>
#include <utils.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

int whois_read(int, char **, const char *);

/*
 *  This function takes a filedescriptor as an argument, makes an whois
 *  query to that host:port. If successfull, it returns the result in the block
 *  of text pointed to by text.
 *
 *  Returns:   -1 Error
 *              0 Success
 */
int
whois_query(struct s_whois_query *wq, char **text)
{
  int ret, sockfd;
  char *tmpqstring;

  printf("[%s %s]\n", _("Querying"), wq->host);

  while (1)
    {
      sockfd = make_connect(wq->host, wq->port);

      if (sockfd < 0)
	{
	  printf(_("[Unable to connect to remote host]\n"));
	  return -1;
	}
      tmpqstring = malloc(strlen(wq->query)+3);
      if (!tmpqstring)
        {
          printf("[%s]\n", _("Error allocating memory"));
          exit(1);
        }
      strncpy(tmpqstring, wq->query, strlen(wq->query)+1);
      strcat(tmpqstring, "\r\n");

      write(sockfd, tmpqstring, strlen(tmpqstring));

      ret = whois_read(sockfd, text, wq->host);

      if (ret < 0)
	{
	  printf("[%s %s:%d]\n", _("Error reading data from"), wq->host,
		 wq->port);
	  exit(1);
	}
      if (redirect)
        {
          ret = lookup_redirect(wq, *text);
          if ((ret < 0) || (ret == 0)) break;
          return 1;
	  break;
        }
      else
        {
          break;
        }
    }
  return 0;
}

/*
 *  This reads input from a file descriptor and stores the contents
 *  in the indicated pointer. Returns the number of bytes stored in
 *  memory or -1 upon error.
 */
int
whois_read(int fd, char **ptr, const char *host)
{
  unsigned int count, start_count;
  int ret;
  char data[MAXBUFSIZE];

  count = 0;

  add_text_to_buffer(ptr, create_string("[%s]\n", host));

  start_count = strlen(*ptr);

  do
    {
      ret = read(fd, data, MAXBUFSIZE-1);
      if (ret >= 0)
	{
	  count += ret;
	  *ptr = realloc(*ptr, start_count+count+1);
	  if (!*ptr)
	    return -1;
	  strncat(*ptr, data, ret);
	}
    }
  while (ret != 0);

  return count;
}

