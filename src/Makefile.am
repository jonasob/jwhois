## Process this file with automake to produce Makefile.in
##
## This file is part of jwhois
## Copyright (C) 1999  Jonas Öberg
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

bin_PROGRAMS = jwhois
jwhois_SOURCES = jwhois.c lexer.l jconfig.c string.c getopt.c getopt1.c regex.c

CFLAGS = -DSYSCONFDIR="\"$(sysconfdir)\"" -DDATADIR="\"$(datadir)\""
INCLUDES = -I$(top_srcdir)/include
