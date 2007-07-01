/*
    This file is part of jwhois
    Copyright (C) 1999,2002,2007  Free Software Foundation, Inc.

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

#ifndef HAVE_STRCASECMP

int
strcasecmp (const char *s1, const char *s2)
{
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  unsigned char c1, c2;

  if (p1 == p2)
    return 0;

  do
    {
      c1 = tolower(*p1++);
      c2 = tolower(*p2++);
      if (c1 == '\0')
	break;
    }
  while (c1 == c2);

  return c1 - c2;
}

#endif

#ifndef HAVE_STRNCASECMP

int
strncasecmp (const char *s1, const char *s2, size_t i)
{
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  unsigned char c1, c2;

  if (p1 == p2)
    return 0;
  if (i == 0)
    return 0;

  do
    {
      c1 = tolower(*p1++);
      c2 = tolower(*p2++);
      if (c1 == '\0')
	break;
    }
  while ( (c1 == c2) && (i-- > 0) );

  return c1 - c2;
}

#endif
