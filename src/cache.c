/*
    This file is part of jwhois
    Copyright (C) 1999  Jonas Öberg

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

#if defined(CACHE) && defined(HAVE_GDBM_OPEN)
# ifdef HAVE_GDBM_H
#  include <gdbm.h>
# endif
#else
# if defined(CACHE) && defined(HAVE_DBM_OPEN)
#  ifdef HAVE_NDBM_H
#   include <ndbm.h>
#  else
#   ifdef HAVE_DBM_H
#    include <dbm.h>
#   endif
#  endif
# endif
#endif

#include <regex.h>
#include <jconfig.h>

#define DBM_MODE           S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP

#if defined(CACHE) && defined(HAVE_GDBM_OPEN)
#define dbm_open(a,b,c)    gdbm_open(a, 0, b, c, 0)
#define DBM_COPTIONS       GDBM_WRCREAT
#define DBM_WOPTIONS       GDBM_WRITER
#define DBM_ROPTIONS       GDBM_READER
#define DBM_IOPTIONS       GDBM_REPLACE
#define dbm_store(a,b,c,d) gdbm_store(a,b,c,d)
#define dbm_close(a)       gdbm_close(a)
#define dbm_fetch(a,b)     gdbm_fetch(a,b)
#else
# if defined(CACHE) && defined(HAVE_DBM_OPEN)
# define DBM_COPTIONS       O_RDWR|O_CREAT
# define DBM_WOPTIONS       O_RDWR
# define DBM_ROPTIONS       O_RDONLY
# define DBM_IOPTIONS       DBM_REPLACE
# endif
#endif

#define DSIZE 2048

#ifndef HAVE_MEMCPY
# define memcpy(d, s, n) bcopy ((s), (d), (n))
#endif

extern int cache;
extern char *cfname;
extern int cfexpire;
extern int verbose;

/*
 *  This function initialises the cache database and possibly converts it
 *  to a newer format if such exists.
 */
void
cache_init()
{
  int ret;
#ifdef CACHE
  datum dbkey = {"#jwhois#cacheversion#1", 22};
  datum dbstore = {"1", 1};
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif

  if (!cache) return;

  umask(0);
  dbf = dbm_open(cfname, DBM_COPTIONS, DBM_MODE);
  if (!dbf)
    {
      fprintf(stderr, "[Unable to initialise cache database]\n");
      cache = 0;
      return;
    }
  ret = dbm_store(dbf, dbkey, dbstore, DBM_IOPTIONS);
  if (ret < 0)
    {
      fprintf(stderr, "[Unable to write to cache database]\n");
      cache = 0;
    }
  dbm_close(dbf);
#endif
}

/*
 *  This reads input from a file descriptor and stores the contents
 *  in the indicated pointer. Returns the number of bytes stored in
 *  memory.
 */
int
cache_fdread(fd, ptr)
     int fd;
     char **ptr;
{
  unsigned int count, ret;
  char data[DSIZE], *tptr;
  time_t *timeptr;

  count = sizeof(time_t);
  *ptr = malloc(sizeof(time_t));
  if (!*ptr)
    {
      fprintf(stderr, "[Error allocating %d bytes of memory]\n", sizeof(time_t));
      exit(1);
    }

  do
    {
      ret = read(fd, data, DSIZE);
      count += ret;
      *ptr = realloc(*ptr, count+1);
      if (!*ptr)
	{
	  fprintf(stderr, "[Error allocating %d bytes of memory]\n", count);
	  exit(1);
	}
      memcpy(*ptr+count-ret, data, ret);
    }
  while (ret != 0);

  timeptr = (time_t *)*ptr;
  *timeptr = time(NULL);
  tptr = *ptr + count;
  *tptr = '\0';

  return count;
}

/*
 *  This reads input from a file descriptor and stores the contents
 *  using the indicated key in the database pointed to by f and
 *  optionally prints it on stdout if print == 1.
 */
void
cache_store(fd, key, host, query, print)
     int fd;
     char *key;
     char *host;
     int print;
{
  char *ptr, *strptr, *bptr, *error;
  struct re_pattern_buffer rpb;
  struct jconfig *j;
  struct re_registers regs;
  char *newhost;
  int ind;
#ifdef CACHE
  datum dbkey;
  datum dbstore;
  int count, ret;
  char data[DSIZE];
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif

  dbkey.dptr = key;
  dbkey.dsize = strlen(key);
  dbstore.dptr = NULL;
  dbstore.dsize = cache_fdread(fd, &dbstore.dptr);

  if (cache)
    {
      dbf = dbm_open(cfname, DBM_WOPTIONS, DBM_MODE);
      if (!dbf)
	{
	  fprintf(stderr, "[Unable to write to cache database]\n");
	}
      else
	{
	  ret = dbm_store(dbf, dbkey, dbstore, DBM_IOPTIONS);
	  if (ret < 0)
	    {
	      fprintf(stderr, "[Unable to write to cache database]\n");
	    }
	  dbm_close(dbf);
	}
    }
  ptr = dbstore.dptr + sizeof(time_t);
#else
  cache_fdread(fd, &ptr);
  ptr += sizeof(time_t);
#endif /* CACHE */

  bptr = malloc(strlen(ptr)+1);
  if (!bptr)
    {
      fprintf(stderr, "[Can not allocate %d bytes of memory]\n",
	      strlen(ptr)+1);
      exit(1);
    }
  memcpy(bptr, ptr, strlen(ptr)+1);

  strptr = (char *)strtok(bptr, "\n");
  while (strptr)
    {
      jconfig_set();
      while (j = jconfig_next("jwhois.content-redirect"))
	{
	  if (strcasecmp(j->key, host) == 0)
	    {
	      rpb.allocated = 0;
	      rpb.buffer = (unsigned char *)NULL;
	      rpb.translate = rpb.fastmap = (char *)NULL;
	      if (error = (char *)re_compile_pattern(j->value, strlen(j->value), &rpb))
		{
		  perror(error);
		  exit(1);
		}
	      ind = re_search(&rpb, strptr, strlen(strptr), 0, 0, &regs);
	      if (ind == 0)
		{
		  newhost = malloc(regs.end[1]-regs.start[1]+2);
		  if (!newhost)
		    {
		      fprintf(stderr, "[Can not allocate %d bytes of memory]\n",
			      regs.end[1]-regs.start[1]+2);
		      exit(1);
		    }
		  strncpy(newhost, strptr+regs.start[1], regs.end[1]-regs.start[1]);
		  newhost[regs.end[1]-regs.start[1]]='\0';
		  if (print)
		    {
		      fprintf(stdout, "[%s: Redirecting to %s]\n", host, newhost);
		    }
		  query_host(key, newhost, 0);
		  return;
		}
	      else if (ind == -2)
		{
		  fprintf(stderr, "[re_search internal error]\n");
		  exit(1);
		}
	    }
	}
      strptr = (char *)strtok(NULL, "\n");
    }

  if (print)
    {
      fprintf(stdout, "[%s]\n", host);
      fprintf(stdout, "%s", ptr);
    }
}

/*
 *  Given a key, this function prints the string containing
 *  the text from the entry. Returns 0 if the key wasn't found or is
 *  outdated. cfexpire is the number of hours we consider an entry to be
 *  current.
 */
int
cache_fetch(key, print)
     char *key;
     int print;
{
#ifdef CACHE
  datum dbkey;
  datum dbstore;
#ifdef HAVE_GDBM_OPEN
  GDBM_FILE dbf;
#else
  DBM *dbf;
#endif
#endif
  time_t *timeptr;

  if (!cache)
    return 0;

#ifdef CACHE
  dbkey.dptr = key;
  dbkey.dsize = strlen(key);

  dbf = dbm_open(cfname, DBM_ROPTIONS, DBM_MODE);
  if (!dbf)
    {
      fprintf(stderr, "[Unable to read cache database]\n");
    }
  else
    {
      dbstore = dbm_fetch(dbf, dbkey);
      timeptr = (time_t *)dbstore.dptr;
      if ( (dbstore.dptr == NULL)
	   || ( ((time(NULL)-*timeptr)/(60*60)) > cfexpire) ) {
	dbm_close(dbf);
	return 0;
      }
      dbm_close(dbf);
    }

  if (print) {
    fprintf(stdout, "[Cached]\n");
    fprintf(stdout, "%s", dbstore.dptr + sizeof(time_t));
  }
  return 1;
#else
  return 0;
#endif /* CACHE */
}
