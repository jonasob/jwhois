/*
    This file is part of jwhois
    Copyright (C) 2001-2002,2007  Free Software Foundation, Inc.

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

#include <config.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include <jwhois.h>
#include <jconfig.h>
#include <whois.h>
#include <http.h>
#include <utils.h>
#include <lookup.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

/*
 * This function performs a HTTP query using an external utility
 * for the given host. The result is stored in the text parameter.
 *
 * Returns -1 on error, 0 on success.
 */
int http_query(struct s_whois_query *wq, char **text)
{
    const char *method = get_whois_server_option(wq->host, "http-method");
    const char *action = get_whois_server_option(wq->host, "http-action");
    const char *element= get_whois_server_option(wq->host, "form-element");
    const char *extra  = get_whois_server_option(wq->host, "form-extra");
    const char *format = get_whois_server_option(wq->host, "query-format");
    char **command;
    char *url;
    char *browser;
    char *browser_arg;
    char *post_file;
    int isget = 1;
    int post_as_file = 0;
    int to_browser[2];
    int from_browser[2];
    struct jconfig *j;

    /* Check host configuration */
    if (!method || !action || !(element || format))
    {
        printf("[HTTP: %s: %s]\n", wq->host, _("HTTP configuration is incomplete:"));
        if (!method) printf("[HTTP: %s %s]\n", _("Option is missing:"), "http-method");
        if (!action) printf("[HTTP: %s %s]\n", _("Option is missing:"), "http-action");
        if (!element && !format) printf("[HTTP: %s %s]\n", _("Option is missing:"), "form-element");
        return -1;
    }

    if (0 == strcmp(method, "POST"))
    {
        isget = 0;
    }
    else if (0 != strcmp(method, "GET"))
    {
        printf("[HTTP: %s: %s]\n", wq->host, _("Option http-method must be \"GET\" or \"POST\".\n"));
        return -1;
    }

    /* Check browser configuration */
    j = jconfig_getone("jwhois", "browser-pathname");
    if (!j)
    {
        printf("[HTTP: %s: %s]\n", _("Option is missing:"),
               "browser-pathname");
        return -1;
    }
    browser = j->value;

    j = jconfig_getone("jwhois", "browser-stdarg");
    if (!j)
    {
        printf("[HTTP: %s: %s]\n", _("Option is missing:"),
               "browser-stdarg");
        return -1;
    }
    browser_arg = j->value;

    j = jconfig_getone("jwhois", "post-as-file");
    if (j && 0 == strcasecmp(j->value, "true"))
    {
        post_as_file = 1;
    }

    /* Build command line */
    if (isget)
    {

        command = (char **) malloc(sizeof (char *) * 5);
        if (!command) return -1;

        command[0] = browser;
        command[1] = command[0];
        command[2] = browser_arg;

        if (format)
        {
            /* Query already formatted */
            command[3] = (char *) malloc(strlen("http://") + strlen(wq->host) +
                                         strlen(action) + 1 +
                                         strlen(wq->query) + 1);
            if (!command[3]) return -1;
            sprintf(command[3], "http://%s%s?%s",
                    wq->host, action, wq->query);
        }
        else
        {
            /* Format query using supplied data */
            command[3] = (char *) malloc(strlen("http://") + strlen(wq->host) +
                                         strlen(action) + 1 +
                                         strlen(element) + 1 +
                                         strlen(wq->query) +
                                         (extra ? strlen(extra) + 1 : 0) + 1);
            if (!command[3]) return -1;
            sprintf(command[3], "http://%s%s?%s=%s%s%s",
                    wq->host, action, element, wq->query,
                    extra ? "&" : "", extra ? extra : "");
        }
        command[4] = NULL;

        url = command[3];
    }
    else
    {
        struct jconfig *j;
        int i = 0;

        command = (char **) malloc(sizeof (char *) * (6 + post_as_file));
        if (!command) return -1;

        command[i ++] = browser;
        command[i ++] = command[0];
        command[i ++] = browser_arg;

        j = jconfig_getone("jwhois", "browser-postarg");
        if (!j)
        {
            printf("[HTTP: %s: %s]\n", _("Option is missing:"),
                   "browser-postarg");
            return -1;
        }
        command[i ++] = j->value;

        if (post_as_file)
        {
            /* Create a temporary file to store POST data in */
            FILE *postdata;
            char tmpfilename[FILENAME_MAX];
            char *tmpdir;
            int fd;

            /* Use $TMPDIR if defined */
            if ((tmpdir = getenv("TMPDIR")) != NULL)
            {
                snprintf(tmpfilename, FILENAME_MAX, "%s/jwhoisXXXXXX", tmpdir);
            }
            else
            {
                strcpy(tmpfilename, "/tmp/jwhoisXXXXXX");
            }

            /* Create the file */
            fd = mkstemp(tmpfilename);
            if (-1 == fd)
            {
                /* Couldn't create temporary file for POST data */
                printf("[HTTP: %s: %s]\n", _("Unable to create temporary file"), strerror(errno));
                exit(-1);
            }

            postdata = fdopen(fd, "w");

            if (format)
            {
                /* Query already formatted */
                fprintf(postdata, "%s\n",
                        wq->query);
            }
            else
            {
                /* Format query using supplied data */
                fprintf(postdata, "%s=%s%s%s\n",
                        element, wq->query,
                        extra ? "&" : "", extra ? extra : "");
            }
            fclose(postdata);

            /* Remember file name so we can clean it up later. */
            command[i ++] = post_file = strdup(tmpfilename);
        }

        command[i] = (char *) malloc(strlen("http://") + strlen(wq->host) +
                                     strlen(action) + 1);
        if (!command[i]) return -1;
        sprintf(command[i], "http://%s%s",
                wq->host, action);
        i ++;

        command[i ++] = NULL;

        url = command[i - 2];
    }

    if (verbose > 1)
    {
        int i;

        fputs("[Running ", stdout);
        for (i = 1; command[i]; i ++)
        {
            fputs(command[i], stdout);
            fputc(' ', stdout);
        }
        puts("]");
    }

    /* Go on and do something */
    printf("[%s http://%s%s]\n", _("Querying"), wq->host, action);
    *text = NULL;

    /* Setup communication pipes */
    if (0 != pipe(from_browser) || 0 != pipe(to_browser))
    {
        free(command);
        return -1;
    }

    /* Run and retrieve data */
    if (0 == fork())
    {
        /* This is the child process */
        close(to_browser[1]);
        close(from_browser[0]);
        dup2(to_browser[0], 0); /* stdin */
        dup2(from_browser[1], 1); /* stdout */
        dup2(from_browser[1], 2); /* stderr */

	/* Drop special privileges */
	setreuid(getuid(), getuid());
	setregid(getgid(), getgid());

        /* Run the browser */
        execv(command[0], &command[1]);

        /* Drats! */
        if (errno)
        {
            printf("[HTTP: %s: %s: %s]\n", _("Unable to run web browser"),
                   command[0], strerror(errno));
        }
        close(to_browser[0]);
        close(from_browser[1]);
        exit(-1);
    }
    else
    {
        /* This is the parent process */
        char data[MAXBUFSIZE];
        int datalen;
        int readbytes;

        close(to_browser[0]);
        close(from_browser[1]);

        if (!isget && !post_as_file)
        {
            struct sigaction sa, old_sa;

            /* Send POST data */
            if (format)
            {
                /* Query already formatted */
                snprintf(data, MAXBUFSIZE, "%s\n---\n",
                         wq->query);
            }
            else
            {
                /* Format query using supplied data */
                snprintf(data, MAXBUFSIZE, "%s=%s%s%s\n---\n",
                         element, wq->query,
                         extra ? "&" : "", extra ? extra : "");
            }
            sa.sa_handler = SIG_IGN;
            sigemptyset (&sa.sa_mask);
            sa.sa_flags = 0;
            sigaction (SIGPIPE, &sa, &old_sa);
            write(to_browser[1], data, strlen(data) + 1);
            sigaction (SIGPIPE, &old_sa, NULL);
        }

        close(to_browser[1]);

        /* Get data from browser */
        *text = NULL;
        datalen = 0;
        data[MAXBUFSIZE - 1] = 0;
        while ((readbytes = read(from_browser[0], data, sizeof data - 1)) > 0)
        {
            *text = (char *) realloc(*text, datalen + readbytes + 1);
            data[readbytes] = 0;
            strcpy(*text + datalen, data);
            datalen += readbytes;
        }

        close(from_browser[0]);
    }

    /* Cleanup */
    free(url);
    free(command);
    wait(NULL);

    if (post_as_file)
    {
        /* Kill the temporary file */
        remove(post_file);
        free(post_file);
    }

    return 0;
}
