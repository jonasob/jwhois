/*
    This file is part of jwhois
    Copyright (C) 2001-2002  Free Software Foundation, Inc.

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

#ifndef UTILS_H
#define UTILS_H

#include "whois.h"

char *get_whois_server_domain_path(const char *hostname);
char *get_whois_server_option(const char *hostname, const char *key);
char *create_string(const char *fmt, ...);
int split_host_from_query(struct s_whois_query *wq);
int make_connect(const char *, int);
int add_text_to_buffer(char **, const char *);


#endif
