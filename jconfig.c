#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif

#include "jconfig.h"

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

struct jconfig *jconfig_next(char *key)
{
	struct jconfig *ptr;

	if (!jconfig_tmpptr) {
		return NULL;
	}

	while (jconfig_tmpptr) {
		if ( (char *)strstr(jconfig_tmpptr->key,key)
		     == jconfig_tmpptr->key) {
			ptr = jconfig_tmpptr;
			jconfig_tmpptr = jconfig_tmpptr->next;
			return ptr;
		}
		jconfig_tmpptr = jconfig_tmpptr->next;
	}
	return NULL;
}

int jconfig_add(char *key, char *value)
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
	strncpy(ptr->key, key, strlen(key));
	strncpy(ptr->value, value, strlen(value));
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
