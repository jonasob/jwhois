#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif

#include "jconfig.h"

int main(void)
{
	struct jconfig *j;

	parse_config(stdin);

	jconfig_set();
	while (j = jconfig_next("jwhois.foo")) {
		printf("%s=%s\n",j->key, j->value);
	}
	jconfig_end();
	return 0;
}
