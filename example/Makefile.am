## Process this file with automake to produce Makefile.in
##
## This file is part of jwhois
## Copyright (C) 2001,2007  Free Software Foundation, Inc.
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

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@if test ! -f $(DESTDIR)$(sysconfdir)/jwhois.conf; then \
		echo "$(INSTALL_DATA) $(top_srcdir)/example/jwhois.conf $(DESTDIR)$(sysconfdir)/jwhois.conf"; \
		$(INSTALL_DATA) $(top_srcdir)/example/jwhois.conf $(DESTDIR)$(sysconfdir)/jwhois.conf; \
	else \
		echo "## ";\
		echo "## Not installing jwhois.conf because you already have a previous version";\
		echo "## installed. You should manually take care of updating your jwhois.conf.";\
		echo "##";\
	fi
