/*
    This file is part of jwhois
    Copyright (C) 1999,2001-2002  Free Software Foundation, Inc.

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
#ifndef JWHOIS_H
#define JWHOIS_H

#ifndef HAVE_MEMCPY
# define memcpy(d, s, n) bcopy ((s), (d), (n))
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2);
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(const char *s1, const char *s2, size_t i);
#endif

#ifndef IPPORT_WHOIS
# define IPPORT_WHOIS 43
#endif

#ifndef MAXBUFSIZE
# define MAXBUFSIZE 1024
#endif

extern int cache;
extern int forcelookup;
extern int verbose;
extern char *ghost;
extern int gport;
extern char *config;

extern char *cfname;
extern int cfexpire;
extern int redirect;
extern int display_redirections;
extern char *whoisservers;
extern int raw_query;
extern int rwhois;
extern int rwhois_limit;
extern char *rwhois_display;
extern int enable_whoisservers;
extern int connect_timeout;

#endif /* JWHOIS_H */
