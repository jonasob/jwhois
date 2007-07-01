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
#include <config.h>
#endif
#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif

#include <jconfig.h>
#include <jwhois.h>

#include <string.h>
#include <ctype.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

static struct jconfig *jconfig_tmpptr = NULL;
static struct jconfig *jconfig_ptr = NULL;
static struct jconfig *jconfig_addptr = NULL;

/*
 *  Resets the pointer to point to the first entry in linked list
 *  containing the configuration parameters.
 */
void
jconfig_set(void)
{
  jconfig_tmpptr = jconfig_ptr;
  return;
}

void
jconfig_end(void)
{
  return;
}

/*
 *  Finds the first occurance in the configuration which matches the domain
 *  and key supplied to the function.
 */
struct jconfig *
jconfig_getone(const char *domain, const char *key)
{
  struct jconfig *ptr;

  if (!jconfig_ptr)
    {
      return NULL;
    }

  ptr = jconfig_ptr;

  while (ptr)
    {
      if ( (char *)strcasecmp(ptr->domain, domain) == 0)
	{
	  if ( (char *)strcasecmp(ptr->key, key) == 0)
	    {
	      return ptr;
	    }
	}
      ptr = ptr->next;
    }
  return NULL;
}

/*
 *  Returns a pointer to the next entry in the configuration file which
 *  matches the specified domain.
 */
struct jconfig *
jconfig_next(const char *domain)
{
  struct jconfig *ptr;
  
  if (!jconfig_tmpptr)
    {
      return NULL;
    }
  while (jconfig_tmpptr)
    {
      if ( (char *)strcasecmp(jconfig_tmpptr->domain, domain) == 0)
	{
	  ptr = jconfig_tmpptr;
	  jconfig_tmpptr = jconfig_tmpptr->next;
	  return ptr;
	}
      jconfig_tmpptr = jconfig_tmpptr->next;
    }
  return NULL;
}

/*
 *  Returns a pointer to the next entry in the configuration file which
 *  matches the specified domain. This differs from the one above in that
 *  it returns matches also for substrings of domain.
 */
struct jconfig *
jconfig_next_all(const char *domain)
{
  struct jconfig *ptr;
  
  if (!jconfig_tmpptr)
    {
      return NULL;
    }
  while (jconfig_tmpptr)
    {
      if ( (char *)strncasecmp(jconfig_tmpptr->domain, domain, strlen(domain)) == 0)
	{
	  ptr = jconfig_tmpptr;
	  jconfig_tmpptr = jconfig_tmpptr->next;
	  return ptr;
	}
      jconfig_tmpptr = jconfig_tmpptr->next;
    }
  return NULL;
}

/*
 *  Adds a key/value pair to the specified domain. line can be used to
 *  pass information to the application on where in the configuration file
 *  this pair was found.
 */
int
jconfig_add(const char *domain, const char *key, const char *value, int line)
{
  struct jconfig *ptr;

  /*
  char *tmps;
  while (isspace(*value)) value++;
  while (isspace(*domain)) domain++;
  while (isspace(*key)) key++;
  tmps = value+strlen(value)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }
  tmps = domain+strlen(domain)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }
  tmps = key+strlen(key)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }
  */

  ptr = malloc(sizeof(struct jconfig));
  if (!ptr)
    {
      return 0;
    }
  ptr->key = malloc(strlen(key)+1);
  if (!ptr->key)
    {
      free(ptr);
      return 0;
    }
  ptr->value = malloc(strlen(value)+1);
  if (!ptr->value)
    {
      free(ptr->key);
      free(ptr);
      return 0;
    }
  ptr->domain = malloc(strlen(domain)+1);
  if (!ptr->domain)
    {
      free(ptr->key);
      free(ptr->value);
      free(ptr);
      return 0;
    }
  strncpy(ptr->key, key, strlen(key)+1);
  strncpy(ptr->value, value, strlen(value)+1);
  strncpy(ptr->domain, domain, strlen(domain)+1);
  ptr->line = line;
  ptr->next = NULL;

  if (jconfig_addptr)
    {
      jconfig_addptr->next = ptr;
      jconfig_addptr = ptr;
    }
  else
    jconfig_addptr = jconfig_ptr = ptr;

  /* This suddenly stopped working. Somehow adding things changed
     direction. Huh? We should find away to match things according
     to the longest match, not according to in which order things
     occur in the configuration file. */
  /*  ptr->next = jconfig_ptr;
      jconfig_ptr = ptr; */

  return 1;
}

/*
 *  Frees all allocated memory.
 */
void
jconfig_free(void)
{
  struct jconfig *ptr;
  
  while (jconfig_ptr) {
    free(jconfig_ptr->value);
    free(jconfig_ptr->key);
    ptr = jconfig_ptr;
    jconfig_ptr = jconfig_ptr->next;
    free(ptr);
  }
}

/*
 *  "Safely" concatenates a string. Reallocating the string to hold the
 *  necessary space.
 */
char *
jconfig_safe_strcat(char *s1, const char *s2)
{
  char *s3;

  if (!s1 || !s2) return NULL;

  s3 = realloc(s1, strlen(s1)+strlen(s2)+1);
  if (!s3)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  strncat(s3, s2, strlen(s2)+1);
  return s3;
}

/*
 *  Allocates memory for and returns a pointer to a quoted line gotten
 *  from `in'.
 */
char *
jconfig_get_quoted(FILE *in, int *line)
{
  char *s1 = NULL;
  int ch, nextch, len = 0;

  s1 = malloc(MAXBUFSIZE);
  if (!s1)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  
  while (!feof(in))
    {
      if (len >= (MAXBUFSIZE-1))
	{
	  printf("[%s: %s %d]\n", config, _("String out of bounds on line"),
		 *line);
	  exit(1);
	}

      ch = fgetc(in);
      switch (ch)
	{
	case '\\':
	  if (!feof(in))
	    nextch = fgetc(in);
	  else
	    nextch = '\\';
	  s1[len++] = nextch;
	  break;
	case '"':
	  s1[len] = '\0';
	  return s1;
	case '\n':
	  s1[len++] = ch;
	  (*line) ++;
	  break;
	default:
	  s1[len++] = ch;
	}
    }
  printf("[%s: %s %d]\n", config, _("End of file looking for '\"' on line"),
	 *line);
  exit(1);
}

/*
 *  Allocates memory for and returns a pointer to a unquoted line gotten
 *  from `in'.
 */
char *
jconfig_get_unquoted(FILE *in, int *line)
{
  char *s1 = NULL;
  int ch, nextch, len = 0;

  s1 = malloc(MAXBUFSIZE);
  if (!s1)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  
  while (!feof(in))
    {
      if (len >= (MAXBUFSIZE-1))
	{
	  printf("[%s: %s %d]\n", config, _("String out of bounds on line"),
		 *line);
	  exit(1);
	}

      ch = fgetc(in);
      switch (ch)
	{
	case '\\':
	  if (!feof(in))
	    nextch = fgetc(in);
	  else
	    nextch = '\\';
	  s1[len++] = nextch;
	  break;
	case ';':
	case ' ':
	case '\t':
	  s1[len] = '\0';
	  ungetc(ch, in);
	  return s1;
	case '\n':
	  s1[len++] = ch;
	  (*line) ++;
	  break;
	default:
	  s1[len++] = ch;
	}
    }
  printf("[%s: %s %d]\n", config, _("Unexpected end of file on line"),
	 *line);
  exit(1);
}

/*
 *  Parses a configuration file and adds found information to the
 *  config structure using jconfig_add.
 */
void
jconfig_parse_file(FILE *in)
{
  int ch, line = 1, nextch;
  char *domain = NULL, *token = NULL, *key = NULL;
  char /* *t1, */ *t2;

  domain = malloc(MAXBUFSIZE);
  if (!domain)
    {
      printf("[%s]\n", _("Error allocating memory"));
      exit(1);
    }
  strncpy(domain, PACKAGE, strlen(PACKAGE)+1);

  while (!feof(in))
    {
      ch = fgetc(in);
      if (ch == '\n')
	line++;
      if (!isspace(ch) && (ch != EOF))
	switch (ch)
	  {
	  case '#':
	    while ((fgetc(in) != '\n') && (!feof(in)));
	    line++;
	    break;
	  case '{':
	    domain = jconfig_safe_strcat(domain, "|");
	    domain = jconfig_safe_strcat(domain, token);
	    break;
	  case '}':
	    /*	    t1 = (char *)strstr(domain, "\\.");
	    if (t1)
	      {
		t1 -= 2;
		*t1 = '\0';
		t2 = (char *)strrchr(domain, '.');
	      }
	      else */
	    t2 = (char *)strrchr(domain, '|');

	    if (t2)
	      *t2 = '\0';
	    if (!feof(in))
	      {
		nextch = fgetc(in);
		if (nextch != ';')
		  ungetc(nextch, in);
	      }
	    break;
	  case '"':
	    if (token)
	      free(token);
	    token = jconfig_get_quoted(in, &line);
	    break;
	  case '=':
	    if (key)
	      {
		printf("[%s: %s %d]\n", config,
		       _("Multiple keys on line"),
		       line);
	      }
	    key = malloc(strlen(token)+1);
	    strcpy(key,token);
	    break;
	  case ';':
	    if (!key)
	      {
		printf("[%s: %s %d]\n", config,
		       _("Missing key on line"), line);
		exit(1);
	      }
	    jconfig_add(domain, key, token, line);
	    free(key);
	    key = NULL;
	    break;
	  default:
	    ungetc(ch, in);
	    if (token)
	      free(token);
	    token = jconfig_get_unquoted(in, &line);
	    break;
	  }
    }
    if (token)
      free(token);
    if (key)
      free(key);
    free(domain);
    
}
