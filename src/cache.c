/*
    This file is part of jwhois
    Copyright (C) 1999-2002,2007  Free Software Foundation, Inc.

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
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#ifdef STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif

#if !defined(NOCACHE) && defined(HAVE_GDBM_OPEN)
# ifdef HAVE_GDBM_H
#  include <gdbm.h>
# endif
#else
# if !defined(NOCACHE) && defined(HAVE_DBM_OPEN)
#  ifdef HAVE_NDBM_H
#   include <ndbm.h>
#  else
#   ifdef HAVE_DBM_H
#    include <dbm.h>
#   else
#    ifdef HAVE_DB1_NDBM_H
#     include <db1/ndbm.h>
#    endif
#   endif
#  endif
# endif
#endif

#include <jconfig.h>
#include <jwhois.h>
#include <cache.h>

#include <string.h>

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

#define DBM_MODE           S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

#if !defined(NOCACHE) && defined(HAVE_GDBM_OPEN)
# define dbm_open(a,b,c)    gdbm_open(a, 0, b, c, 0)
# define DBM_COPTIONS       GDBM_WRCREAT
# define DBM_WOPTIONS       GDBM_WRITER
# define DBM_ROPTIONS       GDBM_READER
# define DBM_IOPTIONS       GDBM_REPLACE
# define dbm_store(a,b,c,d) gdbm_store(a,b,c,d)
# define dbm_close(a)       gdbm_close(a)
# define dbm_fetch(a,b)     gdbm_fetch(a,b)
#else
# if !defined(NOCACHE) && defined(HAVE_DBM_OPEN)
# define DBM_COPTIONS       O_RDWR|O_CREAT
# define DBM_WOPTIONS       O_RDWR
# define DBM_ROPTIONS       O_RDONLY
# define DBM_IOPTIONS       DBM_REPLACE
# endif
#endif

/*
 *  This function initialises the cache database and possibly converts it
 *  to a newer format if such exists. Returns -1 on error. 0 on success.
 */
int
cache_init(void)
{
  int iret;
  char *ret, *ret2;
  struct jconfig *j;
#ifndef NOCACHE
  datum dbkey = {"#jwhois#cacheversion#1", 22};
  datum dbstore = {"1", 1};
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif

  if (!cache) return 0;

  jconfig_set();
  j = jconfig_getone("jwhois", "cachefile");
  if (!j)
    cfname = LOCALSTATEDIR "/jwhois.db";
  else
    cfname = j->value;

  if (verbose>1) printf("[Cache: Cache file name = \"%s\"]\n",cfname);

  jconfig_set();
  j = jconfig_getone("jwhois", "cacheexpire");
  if (!j)
    ret = CACHEEXPIRE;
  else
    ret = j->value;
#ifdef HAVE_STRTOL
  cfexpire = strtol(ret, &ret2, 10);
  if (*ret2 != '\0')
    {
      if (verbose)
	printf("[Cache: %s: %s]\n", _("Invalid expire time"), ret);
      cfexpire = 168;
    }
#else
  cfexpire = atoi(ret2);
#endif /* HAVE_STRTOL */

  if (verbose>1) printf("[Cache: Expire time = %d]\n", cfexpire);

  umask(0);
  dbf = dbm_open(cfname, DBM_COPTIONS, DBM_MODE);
  if (!dbf)
    {
      if (verbose) printf("[Cache: %s %s]\n", _("Unable to open"),
			  cfname);
      cache = 0;
      return -1;
    }
  iret = dbm_store(dbf, dbkey, dbstore, DBM_IOPTIONS);
  if (iret < 0)
    {
      if (verbose) printf("[Cache: %s]\n",
			  _("Unable to store data in cache\n"));
      cache = 0;
    }
  dbm_close(dbf);
#endif
  return 0;
}

/*
 *  This stores the passed text in the database with the key `key'.
 *  Returns 0 on success and -1 on failure.
 */
int
cache_store(char *key, const char *text)
{
#ifndef NOCACHE
  datum dbkey;
  datum dbstore;
  int ret;
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif
  time_t *timeptr;
  char *ptr;

  if (cache)
    {
      dbkey.dptr = key;
      dbkey.dsize = strlen(key);

      ptr = malloc(strlen(text)+sizeof(time_t)+1);
      if (!ptr)
	return -1;
      memcpy(ptr+sizeof(time_t), text, strlen(text)+1);
      
      timeptr = (time_t *)ptr;
      *timeptr = time(NULL);
      
      dbstore.dptr = ptr;
      dbstore.dsize = strlen(text)+sizeof(time_t)+1;
      
      dbf = dbm_open(cfname, DBM_WOPTIONS, DBM_MODE);
      if (!dbf)
	return -1;
      else
	{
	  ret = dbm_store(dbf, dbkey, dbstore, DBM_IOPTIONS);
	  if (ret < 0)
	    return -1;
	  dbm_close(dbf);
	}
    }
#endif
  return 0;
}

/*
 *  Given a key, this function retrieves the text from the database
 *  and checks the expire time on it. If it is still valid data, it
 *  returns the number of bytes in text, else 0 or -1 on error.
 */
int
cache_read(char *key, char **text)
{
#ifndef NOCACHE
  datum dbkey;
  datum dbstore;
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif
#endif
  time_t time_c;

  if (!cache)
    return 0;

#ifndef NOCACHE
  dbkey.dptr = key;
  dbkey.dsize = strlen(key);

  dbf = dbm_open(cfname, DBM_ROPTIONS, DBM_MODE);
  if (!dbf)
    return -1;
  dbstore = dbm_fetch(dbf, dbkey);
  if ((dbstore.dptr == NULL))
    {
      dbm_close(dbf);
      return 0;
    }
  memcpy(&time_c,dbstore.dptr,sizeof(time_c));	/* ensure suitable alignment */
  if ((time(NULL)-time_c)/(60*60) > cfexpire)
    {
      dbm_close(dbf);
      return 0;
    }
  *text = malloc(dbstore.dsize);
  if (!*text)
    return -1;
  memcpy(*text, (char *)(dbstore.dptr)+sizeof(time_t), dbstore.dsize-sizeof(time_t));
  dbm_close(dbf);

  return (dbstore.dsize-sizeof(time_t));
#else
  return 0;
#endif /* !NOCACHE */
}
