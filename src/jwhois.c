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

#ifndef HAVE_MEMCPY
# define memcpy(d, s, n) bcopy ((s), (d), (n))
#endif

#include <jconfig.h>
#include <getopt.h>
#include <regex.h>

#define MAXBUFSIZE	512

#define DO_HELP    0x01
#define DO_VERSION 0x02
static struct option long_options[] = 
{
  {"version", 0, 0, DO_VERSION},
  {"help", 0, 0, DO_HELP},
  {"config", 1, 0, 'c'},
  {"host", 1, 0, 'h'},
  {"port", 1, 0, 'p'},
  {0, 0, 0, 0}
};

void help(void)
{
  printf("%s%s%s%s%s%s%s%s%s%s%s%s", PACKAGE, " version ", VERSION,
	 ", Copyright (C) 1999 Jonas Öberg\n",
	 "This is free software with ABSOLUTELY NO WARRANTY.\n\n",
	 "Usage: jwhois [OPTIONS] [QUERIES...]\n",
	 "  --version               display version number and patch level\n",
	 "  --help                  display this help\n",
	 "  -c FILE, --config=FILE  use FILE as configuration file\n",
	 "  -h HOST, --host=HOST    explicitly query HOST\n",
	 "  -p PORT, --port=PORT    use port number PORT (in conjunction with HOST)\n",
	 "\n\nReport bugs to jonas@coyote.org\n");
}

/*
 *  Makes a query to a host for `val'.  If the port number is zero, the default
 *  value from IPPORT_WHOIS will be used instead.
 */
void query_host(val, host, port)
     char *val;
     char *host;
     int port;
{
  int error, sockfd, ret;
  char *command;
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints, *res;
  struct sockaddr *sa;
#else
  struct protoent *pent;
  struct sockaddr_in remote;
  struct hostent *hostent;
  struct servent *sp = NULL;
#endif

  command = malloc(MAXBUFSIZE);
  if (!command)
    {
      perror("malloc");
      exit(1);
    }

#ifndef HAVE_GETADDRINFO
  remote.sin_family = AF_INET;
#ifndef IPPORT_WHOIS
# define IPPORT_WHOIS 43
#endif
  if (!port) {
    if ((sp = getservbyname("whois", "tcp")) == NULL)
      port = htons(IPPORT_WHOIS);
    else
      port = port = sp->s_port;
  }

  remote.sin_port = htons(port);
#ifdef HAVE_INET_ATON
  ret = inet_aton(host, &remote.sin_addr.s_addr);
#else
  remote.sin_addr.s_addr = inet_addr(host);
  if (remote.sin_addr.s_addr == -1)
    ret = 0;
#endif
  if (!ret)
    {
      hostent = gethostbyname(host);
      if (!hostent)
	{
	  fprintf(stderr, "%s: host unknown\n", host);
	  exit(1);
	}
      memcpy(&remote.sin_addr.s_addr, hostent->h_addr_list[0],
	     sizeof(remote.sin_addr.s_addr));
    }

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (!sockfd)
    {
      perror("Can not create socket");
      exit(1);
    }
  error = connect(sockfd, (struct sockaddr *)&remote, sizeof(struct sockaddr));
  if (error == -1)
    {
      perror(host);
      exit(1);
    }

#else /* HAVE_GETADDRINFO */

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;

  hints.ai_socktype = SOCK_STREAM;
  if (port)
    sprintf(command, "%d", port);
  else
    sprintf(command, "%s", "whois");

  error = getaddrinfo(host, command, &hints, &res);
  if (error)
    {
      perror(gai_strerror(error));
      exit(1);
    }
  else
    {
      while (res)
	{
	  sa = res->ai_addr;
	  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	  if (sockfd == -1)
	    {
	      perror("socket");
	      exit(1);
	    }
	  error = connect(sockfd, res->ai_addr, res->ai_addrlen);
	  if (error == -1)
	    perror("connect");
	  else
	    break;
	  res = res->ai_next;
	}
    }
#endif

  if (error != -1)
    {
      printf("[%s]\n", host);
      write(sockfd, val, strlen(val));
      write(sockfd, "\r\n", 2);
      while (ret = read(sockfd, command, MAXBUFSIZE))
	{
	  fwrite(command, ret, 1, stdout);
	}
      close(sockfd);
    }
}


/*
 *  Looks up an IP address `val' against `block' and returns a pointer
 *  if an entry is found, otherwise NULL.
 */
char *find_cidr(val, block)
     char *val;
     char *block;
{
  struct in_addr ip;
  struct in_addr ipmask;
  struct jconfig *j;
  unsigned int bits, res, a0, a1, a2, a3, ret;
  char *host = NULL;

  res = sscanf(val, "%d.%d.%d.%d", &a0, &a1, &a2, &a3);
  if (res != 4)
    {
      fprintf(stderr, "Invalid IP-number (%s)", val);
      exit(1);
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
		fprintf(stderr, "Invalid netmask (%s) near line %d in"
			" configuration file",
			j->key, j->line);
		exit(1);
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
char *find_regex(val, block)
     char *val;
     char *block;
{
  struct jconfig *j;
  struct re_pattern_buffer      rpb;
  char *error, *ret, *host = NULL;
  int ind;

  jconfig_set();
  while (j = jconfig_next(block))
    {
      if (strcasecmp(j->key, "type") != 0) {
	rpb.allocated = 0;
	rpb.buffer = (unsigned char *)NULL;
	rpb.translate = rpb.fastmap = (char *)NULL;
	if (error = (char *)re_compile_pattern(j->key, strlen(j->key), &rpb))
	  {
	    perror(error);
	    exit(1);
	  }
	ind = re_search(&rpb, val, strlen(val), 0, 0, NULL);
	if (ind == 0)
	  {
	    host = j->value;
	  }
	else if (ind == -2)
	  {
	    fprintf(stderr, "re_search internal error\n");
	    exit(1);
	  }
      }
    }
  jconfig_end();

  return host;
}

/*
 *  Looks up a host and port number from the
 *  material supplied in `val' using `block' as starting point.
 *  Returns 1 on success.
 */
int lookup_host(val, block, host, port)
     char *val;
     char *block;
     char **host;
     int *port;
{
  char deepfreeze[512];
  char *tmpdeep, *tmphost;
  struct jconfig *j;
  char *ret;

  if (!val) return 0;
  if (!block)
    strcpy(deepfreeze, "jwhois.whois-servers");
  else
    sprintf(deepfreeze, "jwhois.%s", block);

  jconfig_set();
  j = jconfig_getone(deepfreeze, "type");
  if (!j)
    *host = find_regex(val, deepfreeze);
  else
    if (strcasecmp(j->value, "regex") == 0)
      *host = find_regex(val, deepfreeze);
    else
      *host = find_cidr(val, deepfreeze);

  if (!*host) return 0;

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
	  fprintf(stderr, "%s: %s %s %s\n",
		  PACKAGE,
		  "Invalid port number for host",
		  *host,
		  "in config file");
	  exit(1);
	}
#else
      *port = atoi((char *)(tmphost+1));
#endif
      *tmphost = '\0';
    }
  return 1;
}

int main(argc, argv)
     int argc;
     char **argv;
{
  int optch, option_index, port = 0;
  char *config = NULL, *host = NULL, *errmsg, *ret;
  FILE *in;
  
  while (1)
    {
      optch = getopt_long(argc, argv, "c:h:p:", long_options, &option_index);
      if (optch == EOF)
	break;
      
      switch (optch)
	{
	case DO_VERSION:
	  printf("%s %s\n", PACKAGE, VERSION);
	  exit(0);
	case DO_HELP:
	  help();
	  exit(0);
	case 'c':
	  if (config) free(config);
	  config = malloc(strlen(optarg)+1);
	  strncpy(config, optarg, strlen(optarg)+1);
	  break;
	case 'h':
	  if (host) free(host);
	  host = malloc(strlen(optarg)+1);
	  strncpy(host, optarg, strlen(optarg)+1);					break;
	case 'p':
#ifdef HAVE_STRTOL
	  port = strtol(optarg, &ret, 10);
	  if (*ret != '\0')
	    {
	      fprintf(stderr, "%s: %s (%s)\n",
		      PACKAGE,
		      "Invalid port number",
		      optarg);
	      exit(1);
	    }
#else
	  port = atoi(optarg);
#endif
	  break;
	}
    }

  if (optind == argc)
    {
      help();
      exit(0);
    }

  if (config)
    {
      in = fopen(config, "r");
      if (!in)
	{
	  perror(config);
	  exit(1);
	}
    }
  else
    {
      in = fopen(SYSCONFDIR "/jwhois.conf", "r");
      if (!in)
	{
	  in = fopen(DATADIR "/jwhois.conf", "r");
	}
    }
  if (in)
    parse_config(in);

  re_syntax_options = RE_SYNTAX_EMACS;
  
  while (optind < argc)
    {
      if (host)
	{
	  query_host(argv[optind++], host, port);
	}
      else
	{
	  if (lookup_host(argv[optind++], NULL, &host, &port)) {
	    query_host(argv[optind-1], host, port);
	  }
	  else
	    query_host(argv[optind-1], DEFAULTHOST, 0);
	}
    }
  
  return 0;
}
