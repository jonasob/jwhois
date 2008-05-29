## Process this file with automake to produce Makefile.in
##
## This file is part of jwhois
## Copyright (C) 1999-2007  Free Software Foundation, Inc.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
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

EXTRA_DIST = config.rpath  m4/ChangeLog config.rpath include/*.h example/jwhois.conf m4/*.m4 jwhois.spec.in jwhois.spec
SUBDIRS = m4 doc gl src example po

AM_CPPFLAGS = -I$(top_srcdir)/gl
LDADD = lib/libgnu.a

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
