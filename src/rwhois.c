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

#include <errno.h>
#include <fcntl.h>

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


/* This register holds the capabilities of the server */
int rwhois_capab;

/* This register tells if we're currently parsing info  */
int info_on;

/* This says what level of recursion we're on */
int recursion_level;

/* This is filled in with the referrals found */
struct s_referrals {
  char *host;
  int port;
  char *autharea;
  struct s_referrals *next;
} *referrals;

#define CAP_CLASS       0x000001
#define CAP_DIRECTIVE   0x000002
#define CAP_DISPLAY     0x000004
#define CAP_FORWARD     0x000008
#define CAP_HOLDCONNECT 0x000010
#define CAP_LIMIT       0x000020
#define CAP_NOTIFY      0x000040
#define CAP_QUIT        0x000080
#define CAP_REGISTER    0x000100
#define CAP_SCHEMA      0x000200
#define CAP_SECURITY    0x000400
#define CAP_SOA         0x000800
#define CAP_STATUS      0x001000
#define CAP_XFER        0x002000
#define CAP_X           0x004000

#define REP_OK       0x01
#define REP_ERROR    0x02
#define REP_INIT     0x03
#define REP_CONT     0x04

static struct {
  char *name;
  int cap;
} capabilities[] = 
{
  {"class", CAP_CLASS},
  {"directive", CAP_DIRECTIVE},
  {"display", CAP_DISPLAY},
  {"forward", CAP_FORWARD},
  {"holdconnect", CAP_HOLDCONNECT},
  {"limit", CAP_LIMIT},
  {"notify", CAP_NOTIFY},
  {"quit", CAP_QUIT},
  {"register", CAP_REGISTER},
  {"schema", CAP_SCHEMA},
  {"security", CAP_SECURITY},
  {"soa", CAP_SOA},
  {"status", CAP_STATUS},
  {"xfer", CAP_XFER},
  {"X", CAP_X},
  {NULL, 0}
};


/*
 *  This function takes a filedescriptor as an argument, makes an rwhois
 *  query to that host:port. If successfull, it returns the result in the block
 *  of text pointed to by text.
 *
 *  Returns:   -1 Error
 *              0 Success
 */
int
rwhois_query_internal(wq, text)
     struct s_whois_query *wq;
     char **text;
{
  int sockfd, ret, limit;
  FILE *f;
  char *reply, *tmpptr, *retptr;
  char *presentation = "-rwhois V-1.5 " PACKAGE " " VERSION "\r\n";

  printf("[Querying %s]\n", wq->host);

  rwhois_capab = 0;
  info_on = 0;
  *text = NULL;

  sockfd = make_connect(wq->host, wq->port);
  if (!sockfd)
    {
      printf("[Unable to connect to remote host]\n");
      return -1;
    }

  add_text_to_buffer(text, create_string("[%s]\n", wq->host));

  f = fdopen(sockfd, "r+");
  if (!f)
    return -1;
  reply = malloc(MAXBUFSIZE);
  if (!reply)
    return -1;

  fprintf(f, "%s", presentation);
  do
    {
      ret = rwhois_read_line(f, reply, text);
    }
  while (ret != REP_OK && ret != REP_ERROR);

  if (ret == REP_ERROR)
    printf("[Protocol error while sending -rwhois option]\n");

  if (verbose)
    {
      printf("[Debug: Rwhois server capabilities (%x):", rwhois_capab);
      ret = 0;
      while (capabilities[ret].cap != 0)
	{
	  if (rwhois_capab & capabilities[ret].cap)
	    {
	      if (ret % 8 == 0)
		printf("]\n[Debug:    ");
	      printf("%s ", capabilities[ret].name);
	    }
	  ret++;
	}
      printf("]\n");
    }

  if (rwhois_display)
    tmpptr = rwhois_display;
  else
    tmpptr = (char *)get_whois_server_option(wq->host, "rwhois-display");

  if (tmpptr)
    {
      if (rwhois_capab & CAP_DISPLAY)
	{
	  if (verbose) printf("[Debug: Setting display to %s]\n", tmpptr);
	  fprintf(f, "-display %s\r\n", tmpptr);
	  do
	    {
	      ret = rwhois_read_line(f, reply, text);
	    }
	  while (ret != REP_OK && ret != REP_ERROR);
	}
      else
	if (verbose) printf("[Debug: Server does not support display]\n");
    }

  if (rwhois_limit)
    limit = rwhois_limit;
  else
    {
      tmpptr = (char *)get_whois_server_option(wq->host, "rwhois-limit");
      if (tmpptr)
	{
#ifdef HAVE_STRTOL
	  limit = strtol(tmpptr, &retptr, 10);
	  if (*retptr != '\0')
	    {
	      printf("[%s (%s)]\n",
		     _("Invalid limit in configuration file"),
		     tmpptr);
	    }
#else
	  limit = atoi(tmpptr);
#endif
	}
      else
	limit = 0;
    }

  if (limit)
    {
      if (rwhois_capab & CAP_LIMIT)
	{
	  if (verbose) printf("[Debug: Setting limit to %d]\n", limit);
	  fprintf(f, "-limit %d\r\n", limit);
	  do
	    {
	      ret = rwhois_read_line(f, reply, text);
	    }
	  while (ret != REP_OK && ret != REP_ERROR);
	}
      else
	if (verbose) printf("[Debug: Server does not support limit]\n");
    }

  if (verbose)
    printf("[Debug: Sending query \"%s\"]\n", wq->query);

  fprintf(f, "%s\r\n", wq->query);

  do
    {
      ret = rwhois_read_line(f, reply, text);
    }
  while (ret != REP_OK && ret != REP_ERROR);

  /*
  fprintf(f, "-quit\r\n");
  do
    {
      ret = rwhois_read_line(f, reply, text);
    }
  while (ret != REP_OK && ret != REP_ERROR);
  */
  fclose(f);
  return 0;
}


/*
 *  This function is the main loop for rwhois queries. It is the only one
 *  called from other files. It calls the internal function above to make
 *  an rwhois query and then follows recursions.
 *
 *  Returns:   -1 Error
 *              0 Success
 */
int
rwhois_query(wq, text)
     struct s_whois_query *wq;
     char **text;
{
  struct s_referral *s, *s_start;
  char *autharea;

  recursion_level = 1;
  referrals = malloc(sizeof(struct s_referrals));
  referrals[recursion_level-1].host = NULL;

  rwhois_query_internal(wq, text);
  if (referrals[recursion_level-1].host) {
    /*    s = s_start = referrals[recursion_level-1]; */
    autharea = NULL;
    while (s)
      {
	if (autharea)
	  if (strcasecmp(autharea, referrals[recursion_level-1].autharea) != 0)
	    {
	      recursion_level++;
	      rwhois_query(referrals[recursion_level-2].host,
				    referrals[recursion_level-2].port,
				    wq->query, text);
	      recursion_level--;
	    }
	autharea = referrals[recursion_level-1].autharea;
	/*	s = s->next; */
      }
  }
  return 0;
}

/*
 *  This reads input from a file descriptor and stores the contents
 *  in the indicated pointer.
 */
int
rwhois_read_line(f, ptr, text)
     FILE *f;
     char *ptr;
     char **text;
{
  if (feof(f))
    {
      printf(_("[Host terminated connection prematurely]\n"));
      exit(1);
    }

  fgets(ptr, MAXBUFSIZE-1, f);
  if (!ptr)
    {
      return REP_ERROR;
    }
  return rwhois_parse_line(ptr, text);
}

/*
 *  This parses the reply sent by the server.
 */
int
rwhois_parse_line(reply, text)
     char *reply;
     char **text;
{
  char *capab, *tmpptr;

  tmpptr = (char *)strchr(reply, '\n');
  if (tmpptr)
    *tmpptr = '\0';
  
  if (info_on)
    {
      add_text_to_buffer(text, create_string("%s\n", reply));
      return REP_CONT;
    }
  if (strncasecmp(reply, "%rwhois", 7) == 0) 
    {
      capab = (char *)strchr(reply, ':')+1;
      if (!capab)
	return REP_ERROR;
      tmpptr = (char *)strchr(capab, ':');
      if (!tmpptr)
	return REP_ERROR;
      *tmpptr = '\0';
      sscanf(capab, "%x", &rwhois_capab);
      return REP_INIT;
    }
  if (strncasecmp(reply, "%ok", 3) == 0)
    return REP_OK;
  if (strncasecmp(reply, "%error", 6) == 0)
    {
      tmpptr = (char *)strchr(reply, ' ');
      if (!tmpptr)
	return REP_ERROR;
      add_text_to_buffer(text, create_string("%s\n", tmpptr+1));
      return REP_ERROR;
    }
  if (strncasecmp(reply, "%referral", 9) == 0)
    {
      
    }
  if (strncasecmp(reply, "%info on", 8) == 0)
    {
      info_on = 1;
      return REP_CONT;
    }
  if (strncasecmp(reply, "%info off", 9) == 0)
    {
      info_on = 0;
      return REP_CONT;
    }
  if (strncasecmp(reply, "%", 1) == 0)
    {
      tmpptr = (char *)strchr(reply, ' ');
      if (!tmpptr)
	return REP_ERROR;
      *tmpptr = '\0';
      if (verbose) printf("[Debug: Unhandled reply: %s]\n", reply+1);
      return REP_CONT;
    }
  add_text_to_buffer(text, create_string("%s\n", reply));
  return REP_CONT;
}
