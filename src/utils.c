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

#include <jwhois.h>

/*
 *  This reads input from a file descriptor and stores the contents
 *  in the indicated pointer. Returns the number of bytes stored in
 *  memory or -1 upon error.
 */
int
fdread(fd, ptr)
     int fd;
     char **ptr;
{
  unsigned int count, ret;
  char data[MAXBUFSIZE];

  count = 0;
  *ptr = NULL;

  do
    {
      ret = read(fd, data, MAXBUFSIZE);
      count += ret;
      if (!*ptr)
	*ptr = malloc(count+1);
      else
	*ptr = realloc(*ptr, count+1);
      if (!*ptr)
	return -1;
      memcpy(*ptr+count-ret, data, ret);
    }
  while (ret != 0);

  if (verbose) printf("[Debug: fdread()=%d]\n", count);
  return count;
}
