#ifndef _JCONFIG_H
#define _JCONFIG_H

struct jconfig {
	char	*domain;
	char	*key;
	char	*value;
	struct jconfig	*next;
};

void jconfig_set(void);
struct jconfig *jconfig_next(char *);
void jconfig_end(void);

int jconfig_add(char *, char *, char *);
void jconfig_free(void);

#endif
