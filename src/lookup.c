/*
    This file is part of jwhois
    Copyright (C) 1999,2001-2003,2007  Free Software Foundation, Inc.

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
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#include <arpa/inet.h>
#include <regex.h>
#include <jwhois.h>
#include <jconfig.h>
#include <whois.h>
#include <lookup.h>
#include <utils.h>
#include <jconfig.h>

#include <string.h>
#include <ctype.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

int lookup_whois_servers(const char *, struct s_whois_query *);

/*
 *  Looks up an IPv4 address `val' against `block' and returns a pointer
 *  if an entry is found, otherwise NULL.
 */
char *
find_cidr(struct s_whois_query *wq, const char *block)
{
  struct in_addr ip;
  struct in_addr ipmaskip;
  struct jconfig *j;
  unsigned int ipmask, bits, res, match_bits;
  unsigned int a0, a1, a2, a3;
  char *host = NULL;

  res = sscanf(wq->query, "%u.%u.%u.%u", &a0, &a1, &a2, &a3);
  if (res == 3) a3 = 0;
  else if (res == 2) a2 = a3 = 0;
  else if (res == 1) a1 = a2 = a3 = 0;
  else if (res != 4) return NULL;

  match_bits = 0;

#ifdef WORDS_BIGENDIAN
  ip.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;
#else
  ip.s_addr = (a0<<24)+(a1<<16)+(a2<<8)+a3;
#endif

  jconfig_set();
  while ((j = jconfig_next(block)) != NULL)
    {
      if (strcasecmp(j->key, "type") != 0) {
	if (!strcasecmp(j->key, "default"))
	  {
	    ipmaskip.s_addr = 0;
	    ipmask = 0;
	    bits = 0;
	  }
	else
	  {
	    res = sscanf(j->key, "%u.%u.%u.%u/%u", &a0, &a1, &a2, &a3,
			 &bits);
	    if (res != 5 || bits > 32)
	      {
		printf("[%s: %s %d]\n",
		       config,
		       _("Invalid netmask on line"),
		       j->line);
		return NULL;
	      }
#ifdef WORDS_BIGENDIAN
            ipmaskip.s_addr = (a3<<24)+(a2<<16)+(a1<<8)+a0;
            ipmask = (0xffffffff>>(32-bits));
#else
            ipmaskip.s_addr = (a0<<24)+(a1<<16)+(a2<<8)+a3;
            ipmask = (0xffffffff<<(32-bits));
#endif
	  }
	if (((ip.s_addr & ipmask) == (ipmaskip.s_addr & ipmask))
            && (bits >= match_bits))
	  {
	    host = j->value;
            match_bits = bits;
	  }
      }
    }
  jconfig_end();

  return host;
}

/*
 * Checks whether IPv6 address `addr` is in the network `net'/`bits`.
 */
#ifdef HAVE_INET_PTON_IPV6
static int ipv6_address_is_in_network(const struct in6_addr *addr,
				      const struct in6_addr *net,
				      unsigned bits)
{
  size_t i;

  for (i = 0; i < bits / 8; i++)
    {
      if (addr->s6_addr[i] != net->s6_addr[i])
	return 0;
    }
  /* i == bits / 8 */
  if (bits % 8 != 0
      && (addr->s6_addr[i] & (0xFFu << (bits % 8))) != net->s6_addr[i])
    return 0;
  return 1;
}
#endif

/*
 *  Looks up an IPv6 address `val' against `block' and returns a pointer
 *  if an entry is found, otherwise NULL.
 */
#ifdef HAVE_INET_PTON_IPV6
static char *
find_cidr6(struct s_whois_query *wq, const char *block)
{
  struct in6_addr query_ip;
  struct in6_addr entry_ip;
  struct jconfig *j;
  unsigned int max_bits, bits, match_bits;
  int res;
  char *p, *addr, *host = NULL;

  p = strchr(wq->query, '/');
  if (p == NULL)
    {
      addr = strdup(wq->query);
      max_bits = 128;
    }
  else
    {
      size_t len;

      if (sscanf(p + 1, "%u", &max_bits) != 1)
	return NULL;
      len = p - wq->query;
      addr = malloc(len + 1);
      memcpy(addr, wq->query, len);
      addr[len] = '\0';
    }
  res = inet_pton(AF_INET6, addr, &query_ip);
  free(addr);
  if (res != 1)
    return NULL;

  match_bits = 0;

  jconfig_set();
  while ((j = jconfig_next(block)) != NULL)
    {
      if (strcasecmp(j->key, "type") == 0)
	continue;
      if (!strcasecmp(j->key, "default"))
	{
	  memset(entry_ip.s6_addr, 0, sizeof(entry_ip.s6_addr));
	  bits = 0;
	}
      else
	{
	  size_t len;

	  p = strchr(j->key, '/');
	  if (p == NULL)
	    {
	      printf(_("[%s: Missing prefix length on line %d]\n"),
		     config, j->line);
	      continue;
	    }
	  if (sscanf(p + 1, "%u", &bits) != 1 || bits > 128)
	    {
	      printf(_("[%s: Invalid prefix length on line %d]\n"), config,
		     j->line);
	      continue;
	    }
	  len = p - j->key;
	  addr = malloc(len + 1);
	  memcpy(addr, j->key, len);
	  addr[len] = '\0';
	  res = inet_pton(AF_INET6, addr, &entry_ip);
	  free(addr);
	  if (res != 1)
	    {
	      printf(_("[%s: Invalid network address on line %d]\n"), config,
		     j->line);
	      continue;
	    }
	}
      if (ipv6_address_is_in_network(&query_ip, &entry_ip, bits)
	  && bits <= max_bits && bits >= match_bits)
	{
	  host = j->value;
	  match_bits = bits;
	}
    }
  jconfig_end();

  return host;
}
#endif

/*
 *  Looks up a string `val' against `block'. Returns a pointer to
 *  a hostname if found, or else NULL. It doesn't necessarily have to
 *  be a hostname though, but can be any general string.
 */
char *
find_regex(struct s_whois_query *wq, const char *block)
{
  struct jconfig *j, *j2;
  struct re_pattern_buffer rpb;
  struct re_registers regs;
  char *error, *match = NULL, *pattern;
  int ind, i, best_match;
  char case_fold[256];

  rpb.allocated = 0;

  for (i = 0; i < 256; i++)
    case_fold[i] = toupper(i);

  best_match = 0;

  jconfig_set();
  while ((j = jconfig_next_all(block)) != NULL)
    {
      if ((strcasecmp(j->key, "default") == 0
           || ((strlen(j->domain) > strlen(block)+1) && (strcasecmp(j->domain+strlen(block)+1, ".*") == 0
           || strcasecmp(j->domain+strlen(block)+1, "default") == 0)))
          && !best_match)
        {
          if (strlen(j->domain) > strlen(block))
            {
              j2 = jconfig_getone(j->domain, "whois-server");
              if (j2)
                {
                  wq->domain = j->domain;
                  match = j2->value;
                }
            }
          else
            {
              match = j->value;
            }
        }
      else if (strcasecmp(j->key, "type") != 0)
	{
	  if (rpb.allocated) {
	    free(rpb.buffer);
	    if (rpb.fastmap)
	      free(rpb.fastmap);
	    if (rpb.regs_allocated != REGS_UNALLOCATED)
	      {
		free(regs.start);
		free(regs.end);
		rpb.regs_allocated = REGS_UNALLOCATED;
	      }
	  }
	  rpb.allocated = 0;
	  rpb.buffer = (unsigned char *)NULL;
	  rpb.translate = case_fold;
	  rpb.fastmap = (char *)NULL;

	  if (strlen(j->domain) > strlen(block))
	    {
              pattern = malloc(strlen(j->domain+strlen(block))+6);
              strncpy(pattern, "\\(", 3);

              if (strncasecmp(j->domain+strlen(block)+1, ".*", 2) == 0)
                strncat(pattern, j->domain+strlen(block)+3,
                        strlen(j->domain+strlen(block)+3)+1);
              else
                strncat(pattern, j->domain+strlen(block)+1,
                        strlen(j->domain+strlen(block)+1)+1);
              strncat(pattern, "\\)", 3);

	      error = (char *)re_compile_pattern(pattern, strlen(pattern), &rpb);
	      free(pattern);
	      if (error != NULL)
		{
		  return NULL;
		}
	      ind = re_search(&rpb, wq->query, strlen(wq->query), 0,
                              strlen(wq->query), &regs);
	      if (ind >= 0 && regs.num_regs >= 1)
		{
		  j2 = jconfig_getone(j->domain, "whois-server");
		  if (j2 && (regs.end[1] - regs.start[1]) >= best_match)
                    {
		      wq->domain = j->domain;
                      best_match = regs.end[1] - regs.start[1];
                      match = j2->value;
                    }
		}
	      else if (ind == -2 || ind == 0)
		{
		  return NULL;
		}
	    }
	  else
	    {
              pattern = malloc(strlen(j->key)+6);
              strncpy(pattern, "\\(", 3);
              if (strncasecmp(j->key, ".*", 2) == 0)
                strncat(pattern, j->key + 2, strlen(j->key+2)+1);
              else
                strncat(pattern, j->key, strlen(j->key)+1);

              strncat(pattern, "\\)", 3);
              error = (char *)re_compile_pattern(pattern, strlen(pattern),&rpb);
	      free(pattern);
	      if (error != NULL)
		{
		  return NULL;
		}
	      ind = re_search(&rpb, wq->query, strlen(wq->query), 0,
                              strlen(wq->query), &regs);

	      if (ind >= 0 && regs.num_regs >= 1)
		{
                  if ((regs.end[1]-regs.start[1]) >= best_match)
                    {
                      best_match = regs.end[1]-regs.start[1];
                      match = j->value;
                    }
		}
	      else if (ind == -2 || ind == 0)
		{
		  return NULL;
		}
	    }
        }
    }

  if (rpb.allocated)
    {
      free(rpb.buffer);
      if (rpb.fastmap)
        free(rpb.fastmap);
      if (rpb.regs_allocated != REGS_UNALLOCATED)
	{
	  free(regs.start);
	  free(regs.end);
	}
    }

  jconfig_end();

  return match;
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
lookup_host(struct s_whois_query *wq, const char *block)
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
  if (!j || strncasecmp(j->value, "regex", 5) == 0)
    wq->host = find_regex(wq, deepfreeze);
  else if (strncasecmp(j->value, "cidr6", 5) == 0) {
#ifdef HAVE_INET_PTON_IPV6
    wq->host = find_cidr6(wq, deepfreeze);
#else
    printf("[%s]\n", _("Warning: Configuration file contains references to IPv6,"));
    printf("[%s]\n", _("         but jwhois was compiled without IPv6 support."));
#endif
  } else
    wq->host = find_cidr(wq, deepfreeze);

  if (!wq->host) wq->host = DEFAULTHOST;

  if (strncasecmp(wq->host, "struct", 6) == 0) {
    tmpdeep = wq->host+7;
    return lookup_host(wq, tmpdeep);
  }

  if (enable_whoisservers)
    if (strncasecmp(wq->host, "whois-servers", 13) == 0) {
      printf("[%s %s]\n", _("Querying"), whoisservers);
      return lookup_whois_servers(wq->query, wq);
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
lookup_redirect(struct s_whois_query *wq, const char *text)
{
  int ind;
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

  while ((j = jconfig_next(domain)) != NULL)
    {
      if (strncasecmp(j->key, "whois-redirect", 14) == 0)
	{
	  memcpy(bptr, text, strlen(text)+1);

	  strptr = (char *)strtok(bptr, "\r\n");
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
                  wq->domain = NULL;
		  return 1;
		}
	      else if (ind == -2)
		return -1;
	      strptr = (char *)strtok(NULL, "\r\n");
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
lookup_whois_servers(const char *val, struct s_whois_query *wq)
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

/* Utility function for lookup_query_format; inserts a string into
 * the allocated buffer, growing it if needed.
 */
static void
add_string(char **bufpos, const char *string, size_t stringlen, char **bufstart, size_t *buflen)
{
  /* Check if string needs to be enlarged */
  if ((*bufpos - *bufstart) + stringlen > *buflen)
    {
      char *new = realloc(*bufstart, *buflen * 2);
      if (!new)
        {
          printf("[%s]\n", _("Error allocating memory"));
          exit(1);
        }
      *buflen *= 2;
      *bufpos = new + (*bufpos - *bufstart);
      *bufstart = new;
    }

  /* Copy string */
  strncpy(*bufpos, string, stringlen);
  *bufpos += stringlen;
}

/* Utility function for lookup_query_format; selects the parts of the
 * domain to add into the query string and calls add_string with it.
 */
static void
add_part(char **bufpos, const char *string, size_t begin, size_t end, char **bufstart, size_t *buflen)
{
  size_t count = 1;
  const char *first = string, *last = string, *p;

  /* Find begin of first section to copy */
  while (count < begin)
    {
      first = strchr(first, '.');
      if (!first)
        return;
      count ++;
      first ++;
      if (!*first)
        return;
      last = first;
    }

  /* Find begin of last section to copy */
  while (count < end)
    {
      last = strchr(last, '.');
      if (!last)
        break;
      count ++;
      last ++;
      if (!*last)
        break;
    }

  /* Find end of last section to copy */
  if (last)
    {
      p = strchr(last, '.');
      if (p)
        last = p;
      else
        last = last + strlen(last);
    }
  else
    last = string + strlen(string);

  /* Copy */
  add_string(bufpos, first, last - first, bufstart, buflen);
}

/*
 * This function looks into the query-format configuration and tries
 * to find out if we need any special considerations for the host we're
 * querying. If so, it returns the proper string for the query. If not,
 * it simply returns a copy of qstring.
 */
char *
lookup_query_format(struct s_whois_query *wq)
{
  char *ret = NULL, *tmpqstring, *tmpptr;
  struct jconfig *j = NULL;
  size_t buflen, dots;

  if (wq->domain)
    j = jconfig_getone(wq->domain, "query-format");
  if (!j)
    {
      ret = get_whois_server_option(wq->host, "query-format");
      if (!ret)
	return strdup(wq->query);
    }
  else 
    {
      ret = j->value;
    }

  /* Count number of dots in domain name */
  dots = 0;
  tmpptr = wq->query;
  while (NULL != (tmpptr = strchr(tmpptr, '.')))
    {
       dots ++;
       tmpptr ++;
    }

  /* Allocate a buffer to work in, we grow it when needed */
  buflen = strlen(ret) + strlen(wq->query) * 5;
  tmpqstring = malloc(buflen);
  if (!tmpqstring)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  tmpptr = tmpqstring;

  while (*ret)
    {
      /* Copy verbatim data */
      const char *dollar = strchr(ret, '$');
      size_t chars = dollar ? (dollar - ret) : strlen(ret);
      if (chars)
        add_string(&tmpptr, ret, chars, &tmpqstring, &buflen);
      ret += chars;

      /* Handle parameter */
      if ('$' == *ret)
        {
          ret ++;
          switch (*ret)
            {
              case '*': /* Entire hostname */
                add_string(&tmpptr, wq->query, strlen(wq->query), &tmpqstring, &buflen);
                ret ++;
                break;

              case '{': /* Field range */
                {
                  size_t startfield = 0, endfield = 0;
                  int right = 0;
                  char *p;
                  ret ++;

                  /* Parse start field */
                  if (isdigit((unsigned char) *ret))
                    {
                      startfield = strtol(ret, &p, 10);
                      if (*p) ret = p;
                    }

                  /* Check direction to count from */
                  if ('+' == *ret)
                    right = 1;

                  /* Check if range */
                  if ('+' == *ret || '-' == *ret)
                    ret ++;
                  else
                    endfield = startfield;

                  /* Parse end field */
                  if (isdigit((unsigned char) *ret))
                    {
                      endfield = strtol(ret, &p, 10);
                      if (*p) ret = p;
                    }

                  /* End parsing */
                  if ('}' == *ret)
                    {
                      ret ++;
                      /* Calculate field numbers */
                      if (right)
                        {
                          if (startfield)
                            {
			      if (dots + 2 < startfield)
				startfield = 1;
			      else
				startfield = dots + 2 - startfield;
                            }
                          if (endfield)
                            endfield = dots + 2 - endfield;
                        }

                      if (startfield && !endfield)
                        {
                          endfield = dots + 1;
                        }

                      if (!startfield && endfield)
                        {
                          startfield = 1;
                        }

                      /* Add fields if we have a valid range */
                      if ((startfield || endfield) && startfield <= endfield)
                        {
                          add_part(&tmpptr, wq->query, startfield, endfield, &tmpqstring, &buflen);
                        }
                    }
                  break;
                }

              case '$': /* Literal */
                add_string(&tmpptr, "$", 1, &tmpqstring, &buflen);
                ret ++;
                break;
            }
        }
    }

  /* Null-terminate */
  add_string(&tmpptr, "", 1, &tmpqstring, &buflen);

  return tmpqstring;
}
