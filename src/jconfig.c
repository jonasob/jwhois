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
#include <config.h>
#endif
#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif

#include <jconfig.h>

static struct jconfig *jconfig_tmpptr = NULL;
static struct jconfig *jconfig_ptr = NULL;

/*
 *  Resets the pointer to point to the first entry in linked list
 *  containing the configuration parameters.
 */
void jconfig_set(void)
{
  jconfig_tmpptr = jconfig_ptr;
  return;
}

void jconfig_end(void)
{
  return;
}

/*
 *  Finds the first occurance in the configuration which matches the domain
 *  and key supplied to the function.
 */
struct jconfig *jconfig_getone(domain, key)
     char *domain;
     char *key;
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
	  if ( (char *)strcasecmp(jconfig_tmpptr->key, key) == 0)
	    {
	      return jconfig_tmpptr;
	    }
	}
      jconfig_tmpptr = jconfig_tmpptr->next;
    }
  return NULL;
}

/*
 *  Returns a pointer to the next entry in the configuration file which
 *  matches the specified domain.
 */
struct jconfig *jconfig_next(domain)
     char *domain;
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
 *  Adds a key/value pair to the specified domain. line can be used to
 *  pass information to the application on where in the configuration file
 *  this pair was found.
 */
int jconfig_add(domain, key, value, line)
     char *domain;
     char *key;
     char *value;
     int line;
{
  struct jconfig *ptr;
  char *tmps;

  while (isspace(*value)) value++;
  while (isspace(*domain)) domain++;
  while (isspace(*key)) key++;
  tmps = value+strlen(value)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }
  tmps = domain+strlen(domain)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }
  tmps = key+strlen(key)-1; while (isspace(*tmps)) { *tmps = 0; tmps--; }

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
  ptr->next = jconfig_ptr;
  jconfig_ptr = ptr;

  return 1;
}

/*
 *  Frees all allocated memory.
 */
void jconfig_free(void)
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
