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
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#include <regex.h>
#include <jwhois.h>
#include <jconfig.h>
#include <whois.h>

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
find_cidr(wq, block)
     struct s_whois_query *wq;
     char *block;
{
  struct in_addr ip;
  struct in_addr ipmaskip;
  unsigned int ipmask;
  struct jconfig *j;
  unsigned int bits, res, a0, a1, a2, a3, ret;
  char *host = NULL;
  char a[4] = {0xde,0xad,0xbe,0xef};
  int b;

  memcpy(&b, a, sizeof(int));

  res = sscanf(wq->query, "%d.%d.%d.%d", &a0, &a1, &a2, &a3);
  if (res == 3) a3 = 0;
  else if (res == 2) a2 = a3 = 0;
  else if (res == 1) a1 = a2 = a3 = 0;
  else if (res != 4) return NULL;
  if (b == 0xdeadbeef) {
      ip.s_addr = (a0<<24)+(a1<<16)+(a2<<8)+a3;
  } else {
      ip.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;
  }
  jconfig_set();
  while (j = jconfig_next(block))
    {
      if (strcasecmp(j->key, "type") != 0) {
	if (!strcasecmp(j->key, "default"))
	  {
	    ipmaskip.s_addr = 0;
	    ipmask = 0;
	  }
	else
	  {
	    res = sscanf(j->key, "%d.%d.%d.%d/%d", &a0, &a1, &a2, &a3,
			 &bits);
	    if (res != 5 || bits < 0 || bits > 32)
	      {
		if (verbose) printf("[%s: %s %d]",
				    config,
				    _("Invalid netmask on line"),
				    j->line);
		return NULL;
	      }
	    if (b == 0xdeadbeef) {
	      ipmaskip.s_addr = (a0<<24)+(a1<<16)+(a2<<8)+a3;
	      ipmask = (0xffffffff<<(32-bits));
	    } else {
	      ipmaskip.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;
	      ipmask = (0xffffffff>>(32-bits));
	    }
	  }
	if ((ip.s_addr & ipmask) == (ipmaskip.s_addr & ipmask))
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
 *  a hostname if found, or else NULL. It doesn't necessarily have to
 *  be a hostname though, but can be any general string.
 */
char *
find_regex(wq, block)
     struct s_whois_query *wq;
     char *block;
{
  struct jconfig *j, *j2;
  struct re_pattern_buffer      rpb, rpb2;
  char *error, *ret, *host = NULL;
  int ind, i;
  char case_fold[256];

  for (i = 0; i < 256; i++)
    case_fold[i] = toupper(i);

  jconfig_set();
  while (j = jconfig_next_all(block))
    {
      if (strcasecmp(j->key, "type") != 0)
	{
	  rpb.allocated = 0;
	  rpb.buffer = (unsigned char *)NULL;
	  rpb.translate = case_fold;
	  rpb.fastmap = (char *)NULL;
	  if (strlen(j->domain) > strlen(block))
	    {
	      if (error = (char *)re_compile_pattern(j->domain+strlen(block)+1,
						     strlen(j->domain+strlen(block)+1),
						     &rpb))
		{
		  return NULL;
		}
	      ind = re_search(&rpb, wq->query, strlen(wq->query), 0, 0, NULL);
	      if (ind == 0)
		{
		  wq->domain = j->domain;
		  jconfig_set();
		  j2 = jconfig_getone(j->domain, "whois-server");
		  if (!j2)
		    return NULL;
		  return j2->value;
		}
	      else if (ind == -2)
		{
		  return NULL;
		}
	    }
	  else
	    {
	      if (error = (char *)re_compile_pattern(j->key, strlen(j->key), &rpb))
		{
		  return NULL;
		}
	      ind = re_search(&rpb, wq->query, strlen(wq->query), 0, 0, NULL);
	      if (ind == 0)
		{
		  return j->value;
		}
	      else if (ind == -2)
		{
		  return NULL;
		}
	    }
      }
    }
  jconfig_end();
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
lookup_host(wq, block)
     struct s_whois_query *wq;
     char *block;
{
  char deepfreeze[512];
  char *tmpdeep, *tmphost;
  struct jconfig *j;
  char *ret;

  if (!wq->query) return -1;
  if (!block)
    strcpy(deepfreeze, "jwhois|whois-servers");
  else
    sprintf(deepfreeze, "jwhois|%s", block);

  jconfig_set();
  j = jconfig_getone("jwhois", "whois-servers-domain");
  if (!j)
    whoisservers = WHOISSERVERS;
  else
    whoisservers = j->value;

  jconfig_set();
  j = jconfig_getone(deepfreeze, "type");
  if (!j)
    wq->host = find_regex(wq, deepfreeze);
  else
    if (strncasecmp(j->value, "regex", 5) == 0)
      wq->host = find_regex(wq, deepfreeze);
    else
      wq->host = find_cidr(wq, deepfreeze);

  if (!wq->host) wq->host = DEFAULTHOST;

  if (strncasecmp(wq->host, "struct", 6) == 0) {
    tmpdeep = wq->host+7;
    return lookup_host(wq, tmpdeep);
  }

  if (enable_whoisservers)
    if (strncasecmp(wq->host, "whois-servers", 13) == 0) {
      printf("[%s %s]\n", _("Querying"), whoisservers);
      return lookup_whois_servers(wq);
    }

  wq->port = 0;
  if (strchr(wq->host, ' '))
    {
      tmphost = (char *)strchr(wq->host, ' ');
#ifdef HAVE_STRTOL
      wq->port = strtol((char *)(tmphost+1), &ret, 10);
      if (*ret != '\0')
	{
	  return -1;
	}
#else
      wq->port = atoi((char *)(tmphost+1));
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
lookup_redirect(wq, text)
     struct s_whois_query *wq;
     char *text;
{
  int num, i, error, ind;
  char *bptr = NULL, *strptr, *ascport, *ret, *tmphost;
  struct re_pattern_buffer rpb;
  struct re_registers regs;
  struct jconfig *j;
  char *domain;

  bptr = malloc(strlen(text)+1);
  if (!bptr)
    return -1;

  domain = (char *)get_whois_server_domain_path(wq->host);
  if (!domain)
    return 0;

  jconfig_set();

  while (j = jconfig_next(domain))
    {
      if (strncasecmp(j->key, "whois-redirect", 14) == 0)
	{
	  memcpy(bptr, text, strlen(text)+1);

	  strptr = (char *)strtok(bptr, "\n");
	  while (strptr)
	    {
	      rpb.allocated = 0;
	      rpb.buffer = (unsigned char *)NULL;
	      rpb.translate = rpb.fastmap = (char *)NULL;
	      if (re_compile_pattern(j->value, strlen(j->value), &rpb))
		return -1;
	      ind = re_search(&rpb, strptr, strlen(strptr), 0, 0, &regs);
	      if (ind == 0)
		{
		  wq->host = malloc(regs.end[1]-regs.start[1]+2);
		  if (!wq->host)
		    return -1;
		  
		  strncpy(wq->host, strptr+regs.start[1],
			  regs.end[1]-regs.start[1]);
		  tmphost = wq->host + regs.end[1]-regs.start[1];
		  *tmphost = '\0';

		  if (regs.num_regs >= 2)
		    {
		      ascport = malloc(regs.end[2]-regs.start[2]+2);
		      if (!ascport)
			return -1;
		      strncpy(ascport, strptr+regs.start[2],
			      regs.end[2]-regs.start[2]);
		      ascport[regs.end[2]-regs.start[2]]='\0';

#ifdef HAVE_STRTOL
		      wq->port = strtol(ascport, &ret, 10);
		      if (*ret != '\0')
			{
			  return -1;
			}
#else
		      wq->port = atoi(ascport);
#endif
		    } /* regs.num_regs == 2 */
		  if (wq->port)
		    {
		      printf("[%s %s:%d]\n", _("Redirected to"), wq->host, wq->port);
		    }
		  else
		    {
		      printf("[%s %s]\n", _("Redirected to"), wq->host);
		    }
		  return 1;
		}
	      else if (ind == -2)
		return -1;
	      strptr = (char *)strtok(NULL, "\n");
	    }
	}
    }
  return 0;
}
 

/*
 *  This is a special hack to look up hosts in the whois-servers.net domain.
 *  It will make recursive queries on the entire domain name, mapped onto
 *  whois-servers.net until it gets a reply saying which whois server to use,
 *  or the TLD is reached without a reply in which case it exits.
 *
 *  Returns: -1  Error
 *           0   Success
 */
int
lookup_whois_servers(val, wq)
  char *val;
  struct s_whois_query *wq;
{
  char *hostname;
  struct hostent *hostent;
  char *tmpptr;
#ifdef HAVE_GETIPNODEBYNAME
  int error_num;
#endif

  if (!val) return -1;
  if (*val == '\0') return -1;

  hostname = malloc(strlen(val)+strlen(whoisservers)+2);
  strncpy(hostname, val, strlen(val)+1);
  strncat(hostname, ".", 1);
  strncat(hostname, whoisservers, strlen(whoisservers));

#ifdef HAVE_GETIPNODEBYNAME
  hostent = (struct hostent *)getipnodebyname(hostname, AF_INET, 0, &error_num);
#else
  hostent = gethostbyname(hostname);
#endif
  if (!hostent)
    {
      tmpptr = (char *)strchr(val, '.');
      if (tmpptr)
	return lookup_whois_servers(tmpptr+1, wq);
      else
	return -1;
    }
  else
    {
      wq->port = 0;
      wq->host = hostent->h_name;
      return 0;
    }
}

/*
 * This function looks into the query-format configuration and tries
 * to find out if we need any special considerations for the host we're
 * querying. If so, it returns the proper string for the query. If not,
 * it simply returns qstring.
 */
char *
lookup_query_format(wq)
     struct s_whois_query *wq;
{
  char *ret = NULL, *tmpqstring, *tmpptr;
  struct jconfig *j = NULL;

  if (wq->domain)
    {
      jconfig_set();
      j = jconfig_getone(wq->domain, "query-format");
    }
  if (!j)
    {
      ret = (char *)get_whois_server_option(wq->host, "query-format");
      if (!ret)
	return wq->query;
    }
  else 
    {
      ret = j->value;
    }
  tmpqstring = malloc(strlen(wq->query)+strlen(ret)+2);
  strncpy(tmpqstring, ret, strlen(ret)+1);

  tmpptr = (char *)strstr(tmpqstring, "$*");
  if (!tmpptr)
    return wq->query;

  strncpy(tmpptr, wq->query, strlen(wq->query)+1);
  strncat(tmpptr, strstr(ret, "$*")+2, strlen((char *)strstr(ret, "$*"))-1);

  return tmpqstring;
}
