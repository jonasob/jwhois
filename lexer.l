%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif 

#include "jconfig.h"

int c, size;
char *token = NULL, *newtoken = NULL;
char *name = NULL, *newname = NULL;
char *value = NULL, *newvalue = NULL;
char *end = NULL;

#define ALLOCATE(a,b)	if (!a) { b = malloc(strlen(yytext)+1); } \
				else { b = realloc(a,strlen(yytext)+1); \
					if (!b) { free(a); perror(PACKAGE); exit(1); } } \
			if (!b) { perror(PACKAGE); exit(1); } \
				else { a = b; }
#define BASE_SIZE	256
#define QUOTED(a,b)	\
	if (!a) { \
		a = malloc(BASE_SIZE); \
		if (!a) { perror(PACKAGE); exit(1); } \
	} else { \
		b = realloc(a,BASE_SIZE); \
		if (!b) { free(a); perror(PACKAGE); exit(1); } \
		a = b; \
	} \
	size = 0; \
	while (c = input()) { \
		if (((size+1) % BASE_SIZE)==1) { \
			b = realloc(a,size+BASE_SIZE); \
			if (!b) { \
				free(a); \
				perror(PACKAGE); \
				exit(1); \
			} \
			a = b; \
		} \
		if ((c == '"') \
		    && (a[size-1] != '\\')) { \
			a[size] = '\0'; \
			break; \
		} \
		a[size++] = c; \
	}

%}

TOKEN	[A-Za-z0-9-]*
WHITE	[ \t\n]*

%x BLOCK TOKEN VALUE
%%
<*>[ \t\n]*			/* eat up whitespace */
<*>"#"[^\n]*			/* eat up comments */

<VALUE>"\""	{
	QUOTED(value,newvalue);
}

<BLOCK>"\""	{
	QUOTED(token,newtoken);
}

<BLOCK>{TOKEN}	{
	ALLOCATE(token,newtoken);
	strncpy(token, yytext, strlen(yytext)+1);
}

<BLOCK>"{"	{
	newname = realloc(name, strlen(name)+strlen(token)+3);
	if (!newname) {
		free(name);
		perror(PACKAGE);
		exit(1);
	}
	name = newname;
	strncat(name, ".", 1);
	strncat(name, token, strlen(token)+1);
}

<VALUE>{TOKEN}	{
	ALLOCATE(value,newvalue);
	strncpy(value,yytext,strlen(yytext)+1);
}

<VALUE>";"		{
	end = malloc(sizeof(name)+sizeof(token)+3);
	if (!end) {
		perror(PACKAGE);
		exit(1);
	}
	strncpy(end, name, strlen(name));
	strncat(end, ".", 1);
	strncat(end, token, strlen(token));
	if (!jconfig_add(end, value)) {
		perror(PACKAGE);
		exit(1);
	}
	BEGIN(BLOCK);
}

<BLOCK>"="	{
	BEGIN(VALUE);
}

<BLOCK>"}"		{
	newname = (char *)strrchr(name,'.');
	if (newname) {
		*newname = '\0';
	} else {
		name[strlen(PACKAGE)] = '\0';
	}
}
<BLOCK>";"		/* eat up */
<*>.	{
	printf("Syntax error on character '%s'\n",yytext);
}
%%
int parse_config(FILE *in)
{
	yyin = in;
	
	name = malloc(strlen(PACKAGE)+1);
	if (!name) {
		perror(PACKAGE);
		exit(1);
	}
	strcpy(name, PACKAGE);
	BEGIN(BLOCK);
	yylex();
}
