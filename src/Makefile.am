## Process this file with automake to produce Makefile.in

bin_PROGRAMS = jwhois
jwhois_LDADD = ../lib/libjwhois.a
jwhois_DEPENDENCIES = ../lib/libjwhois.a
jwhois_SOURCES = jwhois.c lexer.l jconfig.c

CFLAGS = -DDATADIR="\"$(datadir)\""
INCLUDES = -I$(top_srcdir)/include
