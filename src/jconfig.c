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

void jconfig_set(void)
{
	jconfig_tmpptr = jconfig_ptr;
	return;
}

void jconfig_end(void)
{
	return;
}

struct jconfig *jconfig_next(char *domain)
{
	struct jconfig *ptr;

	if (!jconfig_tmpptr) {
		return NULL;
	}

	while (jconfig_tmpptr) {
		if ( (char *)strstr(jconfig_tmpptr->domain,domain)
		     == jconfig_tmpptr->domain) {
			ptr = jconfig_tmpptr;
			jconfig_tmpptr = jconfig_tmpptr->next;
			return ptr;
		}
		jconfig_tmpptr = jconfig_tmpptr->next;
	}
	return NULL;
}

int jconfig_add(char *domain, char *key, char *value)
{
	struct jconfig *ptr;

	ptr = malloc(sizeof(struct jconfig));
	if (!ptr) {
		return 0;
	}
	ptr->key = malloc(strlen(key)+1);
	if (!ptr->key) {
		free(ptr);
		return 0;
	}
	ptr->value = malloc(strlen(value)+1);
	if (!ptr->value) {
		free(ptr->key);
		free(ptr);
		return 0;
	}
	ptr->domain = malloc(strlen(domain)+1);
	if (!ptr->domain) {
		free(ptr->key);
		free(ptr->value);
		free(ptr);
		return 0;
	}
	strncpy(ptr->key, key, strlen(key)+1);
	strncpy(ptr->value, value, strlen(value)+1);
	strncpy(ptr->domain, domain, strlen(domain)+1);
	ptr->next = jconfig_ptr;
	jconfig_ptr = ptr;
	return 1;
}

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
