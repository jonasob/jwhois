#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
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
	{0, 0, 0, 0}
};

void help(void)
{
	printf("%s%s%s%s%s%s%s%s%s%s%s", PACKAGE, " version ", VERSION,
		", Copyright (C) 1999 Jonas Öberg\n",
		"This is free software with ABSOLUTELY NO WARRANTY.\n\n",
		"Usage: jwhois [OPTIONS] [QUERIES...]\n",
		"  --version               display version number and patch level\n",
		"  --help                  display this help\n",
                "  -c FILE, --config=FILE  use FILE as configuration file\n",
		"  -h HOST, --host=HOST    explicitly query HOST\n",
		"\n\nReport bugs to jonas@coyote.org\n");
}

int query_host(char *host, char *val)
{
	int sockfd, ret;
	struct protoent *pent;
	struct sockaddr_in remote;
	struct hostent *hostent;
	char *command;

	command = malloc(MAXBUFSIZE);
	if (!command) {
		perror("");
		exit(1);
	}
	remote.sin_family = AF_INET;
	remote.sin_port = htons(IPPORT_WHOIS);
	ret = inet_aton(host, &remote.sin_addr.s_addr);
	if (!ret) {
		hostent = gethostbyname(host);
		if (!hostent) {
			fprintf(stderr, "%s: host unknown\n", host);
			exit(1);
		}
		ret = inet_aton(inet_ntoa(*(struct in_addr *)(hostent->h_addr_list[0])), &remote.sin_addr.s_addr);
		if (!ret) {
			fprintf(stderr, "%s: error looking up host\n", host);
			exit(1);
		}
	}
	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	if (!sockfd) {
		perror("Can not create socket");
		exit(1);
	}
	ret = connect(sockfd, (struct sockaddr *)&remote, sizeof(struct sockaddr));
	if (ret == -1) {
		perror(host);
		exit(1);
	}
	fprintf(stderr, "[%s]\n", host);
	write(sockfd, val, strlen(val));
	write(sockfd, "\r\n", 2);
	while (ret = read(sockfd, command, MAXBUFSIZE)) {
		fwrite(command, ret, 1, stdout);
	}
	close(sockfd);
}

void make_query(char *val)
{
	struct jconfig *j;
	struct re_pattern_buffer	rpb;
	char *error, *host = DEFAULTHOST;
	int ind;

	jconfig_set();
	while (j = jconfig_next("jwhois.whois-servers")) {
		rpb.allocated = 0;
		rpb.buffer = (unsigned char *)NULL;
		rpb.translate = rpb.fastmap = (char *)NULL;
		if (error = (char *)re_compile_pattern(j->key, strlen(j->key),
			&rpb)) {
			perror(error);
			exit(1);
		}
		ind = re_search(&rpb, val, strlen(val), 0, 0, NULL);
		if (ind == 0) {
			host = j->value;
		} else if (ind == -2) {
			fprintf(stderr, "re_search internal error\n");
			exit(1);
		}
	}
	jconfig_end();
	query_host(host,val);
	return;
}

int main(int argc, char **argv)
{
	int optch, option_index;
	char *config = NULL, *host = NULL, *errmsg;
	FILE *in;

	while (1) {
		optch = getopt_long(argc, argv, "c:h:", long_options, &option_index);
		if (optch == EOF)
			break;

		switch (optch) {
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
		}
	}

	if (optind == argc) {
		help();
		exit(0);
	}

	if (config) {
		in = fopen(config, "r");
		if (!in) {
			perror(config);
			exit(1);
		}
	} else {
		in = fopen(DATADIR "/jwhois.conf", "r");
	}
	if (in)
		parse_config(in);

	re_syntax_options = RE_SYNTAX_EMACS;

	while (optind < argc) {
		if (host) {
			query_host(host, argv[optind++]);
		} else {
			make_query(argv[optind++]);
		}
	}

	return 0;
}
