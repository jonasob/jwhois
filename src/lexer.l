%{
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif 

#include <jconfig.h>

int c, size, line = 1;
char *token = NULL;
char *name = NULL;
char *value = NULL;
char *end = NULL;
char *new;

#define ALLOCATE(a)	if (!a) { new = malloc(strlen(yytext)+2); } \
				else { new = realloc(a,strlen(yytext)+2); \
					if (!new) { free(a); perror(PACKAGE); exit(1); } } \
			if (!new) { perror(PACKAGE); exit(1); } \
				else { a = new; }
%}

TOKEN	[A-Za-z0-9-]*

%x BLOCK VALUE
%%
<*>[ \t]*			/* eat up whitespace */
<*>[\n]				line++;
<*>"#"[^\n]*			/* eat up comments */

<VALUE>"\""[[:print:]]*"\""	{
	ALLOCATE(value);
	strncpy(value,yytext+1,strlen(yytext));
	value[strlen(yytext)-2] = '\0';
}

<BLOCK>"\""[[:print:]][^\"]*"\""	{
	ALLOCATE(token);
	strncpy(token,yytext+1,strlen(yytext));
	token[strlen(yytext)-2] = '\0';
}

<BLOCK>{TOKEN}	{
	ALLOCATE(token);
	strncpy(token, yytext, strlen(yytext)+1);
}

<VALUE>{TOKEN}	{
	ALLOCATE(value);
	strncpy(value,yytext,strlen(yytext)+1);
}

<BLOCK>"{"	{
	new = realloc(name, strlen(name)+strlen(token)+3);
	if (!new) {
		free(name);
		perror(PACKAGE);
		exit(1);
	}
	name = new;
	strncat(name, ".", 1);
	strncat(name, token, strlen(token)+1);
}

<VALUE>";"		{
	if (!jconfig_add(name, token, value)) {
		perror(PACKAGE);
		exit(1);
	}
	BEGIN(BLOCK);
}

<BLOCK>"="	{
	BEGIN(VALUE);
}

<BLOCK>"}"		{
	new = (char *)strrchr(name,'.');
	if (new) {
		*new = '\0';
	} else {
		name[strlen(PACKAGE)] = '\0';
	}
}
<BLOCK>";"		/* eat up */
<*>.	{
	printf("%s: configuration syntax error near character '%s' on line %d\n",PACKAGE,yytext,line);
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
