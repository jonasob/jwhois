/*
    This file is part of jwhois
    Copyright (C) 1999,2001-2002,2007  Free Software Foundation, Inc.

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
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include <jconfig.h>
#include <jwhois.h>
#include <regex.h>
#include <whois.h>
#include <http.h>
#include <cache.h>
#include <init.h>
#include <lookup.h>
#include <rwhois.h>
#include <utils.h>

#include <errno.h>
#include <string.h>

#ifdef HAVE_ICONV
# include <iconv.h>
# include <langinfo.h>
#endif

#ifdef LIBIDN
# include <idna.h>
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

int jwhois_query(struct s_whois_query *, char **);

int
main(int argc, char **argv)
{
  int optind, count = 0, ret, rc = 0;
  char *qstring = NULL, *text, *cachestr, *idn;
  struct s_whois_query wq;

  setlocale(LC_ALL, "");
#ifdef ENABLE_NLS
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
  timeout_init();

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
          printf("[%s]\n", _("Error allocating memory"));
          exit(1);
        }
      memcpy(qstring+count-strlen(argv[optind])-1,
	     argv[optind],
	     strlen(argv[optind])+1);
      strcat(qstring, " ");
      optind++;
    }
  qstring[strlen(qstring)-1] = '\0';
#ifdef LIBIDN
  rc = idna_to_ascii_lz(qstring, &idn, 0);
  if (rc != IDNA_SUCCESS)
    {
      printf("[IDN encoding of '%s' failed with error code %d]\n", qstring, rc);
      exit(1);
    }
  wq.query = strdup(idn);
  free(idn);
#else
  wq.query = qstring;
#endif

  if (ghost)
    {
      if (verbose>1) printf("[Calling %s:%d directly]\n", ghost, gport);
      wq.host = ghost;
      wq.port = gport;
    }
  else if (split_host_from_query(&wq))
    {
      if (verbose>1) printf("[Calling %s directly]\n", wq.host);
    }
  else
    {
      ret = lookup_host(&wq, NULL);
      if (ret < 0)
	{
	  printf("[%s]\n", _("Fatal error searching for host to query"));
	  exit(1);
	}
    }

  text = NULL;

#ifndef NOCACHE
  cachestr = malloc(strlen(wq.query) + strlen(wq.host) + 1);
  if (!cachestr)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  snprintf(cachestr, strlen(wq.query) + strlen(wq.host) + 1, "%s:%s",
           wq.host, wq.query);

  if (!forcelookup && cache) {
    if (verbose>1) printf("[Looking up entry in cache]\n");
    ret = cache_read(cachestr, &text);
    if (ret < 0)
      {
	printf("[%s]\n", _("Error reading cache"));
	exit(1);
      }
    else if (ret > 0)
      {
	printf("[%s]\n%s", _("Cached"), text);
	exit(0);
      }
  }
#endif

  jwhois_query(&wq, &text);

#ifndef NOCACHE
  if (cache) {
    if (verbose>1) printf("[Storing in cache]\n");
    ret = cache_store(cachestr, text);
    if (ret < 0)
      {
	printf("[%s]\n", _("Error writing to cache"));
      }
  }
#endif

  printf("%s", text);
  exit(0);
}

/*
 * Attempt to convert string if result encoding is specified in the config
 * file.
 * */
static char *
convert_charset(struct s_whois_query *wq, char *curdata)
{
#ifdef HAVE_ICONV
  const char *charset;

  charset = get_whois_server_option(wq->host, "answer-charset");
  if (charset != NULL)
    {
      iconv_t cd;

      cd = iconv_open(nl_langinfo(CODESET), charset);
      if (cd != (iconv_t)-1)
	{
	  char *buf, *src;
	  size_t src_left, dest_size, dest_pos, res;

	  src = curdata;
	  src_left = strlen(src);
	  dest_size = src_left;
	  buf = malloc(dest_size);
	  if (buf == NULL)
	    goto error;
	  dest_pos = 0;

	  res = 0;
	  while (src_left != 0)
	    {
	      char *dest;
	      size_t dest_left;
	      
	      dest = buf + dest_pos;
	      dest_left = dest_size - dest_pos;
	      res = iconv(cd, &src, &src_left, &dest, &dest_left);
	      if (res == (size_t)-1 && errno != E2BIG)
		goto error;
	      dest_pos = dest - buf;
	      dest_size *= 2;
	      buf = realloc(buf, dest_size);
	      if (buf == NULL)
		goto error;
	    }
	  buf[dest_pos] = 0;
	  
	  iconv_close(cd);
	  free (curdata);
	  return buf;
	  
	error:
	  free(buf);
	  iconv_close(cd);
	}
    }
#endif
  (void)wq;
  return curdata;
}

/*
 *  This is the routine that actually performs a query. It selects
 *  the method to use for the host and then calls the correct routine
 *  to make the query. If the return value of the subroutine is above
 *  0, it found a redirect to another server, so jwhois_query() promptly
 *  follows it there. A return value of -1 is always a fatal error.
 */
int
jwhois_query(struct s_whois_query *wq, char **text)
{
  char *tmp, *tmp2, *oldquery, *curdata;
  int ret;

  if (!display_redirections)
    *text = NULL;
  
  if (!raw_query)
    {
      oldquery = wq->query;
      wq->query = (char *)lookup_query_format(wq);
    }

  tmp = (char *)get_whois_server_option(wq->host, "rwhois");
  tmp2 = (char *)get_whois_server_option(wq->host, "http");
  curdata = NULL;

  if ( (tmp && 0 == strcasecmp(tmp, "true")) || rwhois )
    {
      ret = rwhois_query(wq, &curdata);
    }
  else
    {
      if (tmp2 && 0 == strcasecmp(tmp2, "true"))
	{
	  ret = http_query(wq, &curdata);
	}
      else
	{
	  ret = whois_query(wq, &curdata);
	}
    }

  if (!raw_query)
    {
      free(wq->query);
      wq->query = oldquery;
    }

  if (ret < 0)
    {
      exit(1);
    }
  if (curdata != NULL)
    {
      curdata = convert_charset(wq, curdata);
      if (*text == NULL)
	*text = curdata;
      else
	{
	  *text = realloc(*text, strlen (*text) + strlen (curdata) + 1);
	  if (*text == NULL)
	    exit(1);
	  strcat(*text, curdata);
	  free(curdata);
	}
    }
  if (ret > 0)
    {
      return jwhois_query(wq, text);
    }
  else
    return 0;
}
