/*
    This file is part of jwhois
    Copyright (C) 2001  Free Software Foundation, Inc.

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

#include <regex.h>
#include <jwhois.h>
#include <jconfig.h>
#include <whois.h>

#include <errno.h>

#ifdef HAVE_LIBINTL_H
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

/*
 *  This function takes a filedescriptor as an argument, makes an whois
 *  query to that host:port. If successfull, it returns the result in the block
 *  of text pointed to by text.
 *
 *  Returns:   -1 Error
 *              0 Success
 */
int
whois_query(wq, text)
     struct s_whois_query *wq;
     char **text;
{
  int ret, sockfd;
  char *tmpqstring;

  printf("[Querying %s]\n", wq->host);
  *text = NULL;
  while (1)
    {
      if (!raw_query)
	tmpqstring = (char *)lookup_query_format(wq);
      else
	tmpqstring = wq->query;

      if (verbose) printf("[Debug: Formatted query: \"%s\"]\n", tmpqstring);

      sockfd = make_connect(wq->host, wq->port);

      if (sockfd < 0)
	{
	  printf("[Unable to connect to remote host]\n");
	  return -1;
	}
      tmpqstring = realloc(tmpqstring, strlen(tmpqstring)+3);
      if (!tmpqstring)
        {
          printf("[%s]\n", _("error allocating memory"));
          exit(1);
        }
      strcat(tmpqstring, "\r\n");
      write(sockfd, tmpqstring, strlen(tmpqstring));

      ret = whois_read(sockfd, text, wq->host);
      if (ret < 0)
	{
	  printf("[%s %s:%d]\n", _("error reading data from"), wq->host,
		 wq->port);
	  exit(1);
	}
      if (redirect)
        {
          ret = lookup_redirect(wq->host, *text, wq);
          if ((ret < 0) || (ret == 0)) break;
        }
      else
        {
          break;
        }
    }
}

/*
 *  This reads input from a file descriptor and stores the contents
 *  in the indicated pointer. Returns the number of bytes stored in
 *  memory or -1 upon error.
 */
int
whois_read(fd, ptr, host)
     int fd;
     char **ptr;
     char *host;
{
  unsigned int count, start_count;
  int ret;
  char data[MAXBUFSIZE];
  char *tmpptr;

  count = 0;

  if (!display_redirections)
    {
      free(*ptr);
      *ptr = NULL;
    }

  add_text_to_buffer(&*ptr, create_string("[%s]\n", host));

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

