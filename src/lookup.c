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

/*
 *  Looks up an IP address `val' against `block' and returns a pointer
 *  if an entry is found, otherwise NULL.
 */
char *
find_cidr(val, block)
     char *val;
     char *block;
{
  struct in_addr ip;
  struct in_addr ipmask;
  struct jconfig *j;
  unsigned int bits, res, a0, a1, a2, a3, ret;
  char *host = NULL;

  if (verbose) printf("[Debug: find_cidr(\"%s\", \"%s\")]\n", val, block);

  res = sscanf(val, "%d.%d.%d.%d", &a0, &a1, &a2, &a3);
  if (res != 4)
    {
      return NULL;
    }
  ip.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;

  jconfig_set();
  while (j = jconfig_next(block))
    {
      if (strcasecmp(j->key, "type") != 0) {
	if (!strcasecmp(j->key, "default"))
	  {
	    ipmask.s_addr = 0;
	  }
	else
	  {
	    res = sscanf(j->key, "%d.%d.%d.%d/%d", &a0, &a1, &a2, &a3,
			 &bits);
	    if (res != 5)
	      {
		if (verbose) printf("[%s: %s %d]",
				    config,
				    _("invalid netmask on line"),
				    j->line);
		return NULL;
	      }
	    ipmask.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;
	    ipmask.s_addr &= (0xffffffff>>bits);
	  }
	if ((ip.s_addr & ipmask.s_addr) == ipmask.s_addr)
	  {
	    host = j->value;
	  }
      }
    }
  jconfig_end();

  return host;
}

/*
 *  Looks up a string `val' against `block'. Returns a pointer to
 *  a hostname if found, or else NULL.
 */
char *
find_regex(val, block)
     char *val;
     char *block;
{
  struct jconfig *j;
  struct re_pattern_buffer      rpb;
  char *error, *ret, *host = NULL;
  int ind;

  if (verbose) printf("[Debug: find_regex(\"%s\", \"%s\")]\n", val, block);

  jconfig_set();
  while (j = jconfig_next(block))
    {
      if (strcasecmp(j->key, "type") != 0) {
	rpb.allocated = 0;
	rpb.buffer = (unsigned char *)NULL;
	rpb.translate = rpb.fastmap = (char *)NULL;
	if (error = (char *)re_compile_pattern(j->key, strlen(j->key), &rpb))
	  {
	    return NULL;
	  }
	ind = re_search(&rpb, val, strlen(val), 0, 0, NULL);
	if (ind == 0)
	  {
	    host = j->value;
	  }
	else if (ind == -2)
	  {
	    return NULL;
	  }
      }
    }
  jconfig_end();

  return host;
}

/*
 *  Looks up a string `val' against `block'. Returns in matches a pointer to
 *  a list of entries or NULL if none found. Should return all
 *  matches. Maximum of 128 matches.
 *  Returns: -1  Memory allocation error
 *           -2  Internal regex error
 *           Any other  Success (number of entries found)
 */
int
find_regex_all(val, block, matches)
     char *val;
     char *block;
     char **matches;
{
  struct jconfig *j;
  struct re_pattern_buffer      rpb;
  char *error, *ret, *host = NULL;
  int ind, num;

  if (verbose) printf("[Debug: find_regex_all(\"%s\", \"%s\")]\n", val, block);
  
  for (num = 0; num <= 127; num++)
    matches[num] = NULL;
  num = 0;
  
  jconfig_set();
  while (j = jconfig_next(block))
    {
      if (verbose) printf("[Debug: j->key = \"%s\"]\n", j->key);
      rpb.allocated = 0;
      rpb.buffer = (unsigned char *)NULL;
      rpb.translate = rpb.fastmap = (char *)NULL;
      if (re_compile_pattern(j->key, strlen(j->key), &rpb))
	return -2;
      ind = re_search(&rpb, val, strlen(val), 0, 0, NULL);
      if (ind == 0)
	{
	  if (verbose) printf("[Debug: Match j->value = \"%s\"]\n", j->value);
	  matches[num++] = j->value;
	}
      else if (ind == -2)
	{
	  return -2;
	}
    }
  jconfig_end();

  return num;
}

/*
 *  Looks up a host and port number from the material supplied in `val'
 *  using `block' as starting point.  If `block' is NULL, use
 *  "jwhois.whois-servers" as base.
 *  
 *  Returns: -1   Error
 *           0    Success.
 */
int
lookup_host(val, block, host, port)
     char *val;
     char *block;
     char **host;
     int *port;
{
  char deepfreeze[512];
  char *tmpdeep, *tmphost;
  struct jconfig *j;
  char *ret;

  if (!val) return -1;
  if (!block)
    strcpy(deepfreeze, "jwhois.whois-servers");
  else
    sprintf(deepfreeze, "jwhois.%s", block);

  jconfig_set();
  j = jconfig_getone(deepfreeze, "type");
  if (!j)
    *host = find_regex(val, deepfreeze);
  else
    if (strncasecmp(j->value, "regex", 5) == 0)
      *host = find_regex(val, deepfreeze);
    else
      *host = find_cidr(val, deepfreeze);

  if (!*host) *host = DEFAULTHOST;

  if (strncasecmp(*host, "struct", 6) == 0) {
    tmpdeep = *host+7;
    return lookup_host(val, tmpdeep, host, port);
  }

  *port = 0;
  if (strchr(*host, ' '))
    {
      tmphost = (char *)strchr(*host, ' ');
#ifdef HAVE_STRTOL
      *port = strtol((char *)(tmphost+1), &ret, 10);
      if (*ret != '\0')
	{
	  return -1;
	}
#else
      *port = atoi((char *)(tmphost+1));
#endif
      *tmphost = '\0';
    }
  return 0;
}

/*
 *  This looks through `block' looking for matching hostnames and
 *  then performs a regexp search on the contents of `text'. If found,
 *  returns 1 and sets `host' and `port' accordingly. If `port' is not
 *  found in the match context, sets `port' to 0.
 *  If `block' is NULL, use "jwhois.content-redirect" as base.
 *
 *  Returns: -1   Error
 *           0    None found
 *           1    Match found
 */
int
lookup_redirect(search_host, block, text, host, port)
     char *search_host;
     char *block;
     char *text;
     char **host;
     int *port;
{
  int num, i, error, ind;
  char *matches[128], *bptr = NULL, *strptr, *ascport, *ret, *tmphost;
  struct re_pattern_buffer rpb;
  struct re_registers regs;

  if (verbose) printf("[Debug: lookup_redirect(\"%s\", ...,\"%s\", ...)]\n",
		      search_host, text);

  bptr = malloc(strlen(text)+1);
  if (!bptr)
    return -1;

  if (!block)
    num = find_regex_all(search_host, "jwhois.content-redirect", &matches);
  else
    num = find_regex_all(search_host, block, &matches);
  if (verbose) printf("[Debug: find_regex_all() = %d]\n", num);

  i = 0;
  while (i < num)
    {
      if (verbose) printf("[Debug: lookup_redirect \"%s\"]\n", matches[i]);
      memcpy(bptr, text, strlen(text)+1);

      strptr = (char *)strtok(bptr, "\n");
      while (strptr)
	{
	  rpb.allocated = 0;
	  rpb.buffer = (unsigned char *)NULL;
	  rpb.translate = rpb.fastmap = (char *)NULL;
	  if (re_compile_pattern(matches[i], strlen(matches[i]), &rpb))
	    return -1;
	  ind = re_search(&rpb, strptr, strlen(strptr), 0, 0, &regs);
          if (verbose) printf("[Debug: re_search(...,\"%s\",,,) = %d\n", strptr, ind);
	  if (ind == 0)
	    {
	      *host = malloc(regs.end[1]-regs.start[1]+2);
	      if (!*host)
		return -1;

	      strncpy(*host, strptr+regs.start[1],
		      regs.end[1]-regs.start[1]);
	      tmphost = *host + regs.end[1]-regs.start[1];
	      *tmphost = '\0';
              if (verbose) printf("[Debug: matched: %s]\n", *host);

	      if (regs.num_regs >= 2)
		{
		  ascport = malloc(regs.end[2]-regs.start[2]+2);
		  if (!ascport)
		    return -1;
		  strncpy(ascport, strptr+regs.start[2],
			  regs.end[2]-regs.start[2]);
		  ascport[regs.end[2]-regs.start[2]]='\0';

#ifdef HAVE_STRTOL
		  *port = strtol(ascport, &ret, 10);
		  if (*ret != '\0')
		    {
		      return -1;
		    }
#else
		  *port = atoi(ascport);
#endif
		} /* regs.num_regs == 2 */
	      printf("[%s %s:%d]\n", _("redirected to"), *host, *port);
	      return 1;
	    }
	  else if (ind == -2)
	    return -1;
	  strptr = (char *)strtok(NULL, "\n");
	}
      i++;
    }
  return 0;
}
