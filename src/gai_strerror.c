/*  Copyright (C) 1997 Free Software Foundation, Inc.
    Copyright (C) 1999 Jonas Öberg

    This file is part of jwhois

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

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifndef HAVE_GAI_STRERROR

static struct
  {
    int code;
    const char *msg;
  }
values[] =
  {
    { EAI_ADDRFAMILY, "Address family for hostname not supported" },
    { EAI_AGAIN, "Temporary failure in name resolution" },
    { EAI_BADFLAGS, "Bad value for ai_flags" },
    { EAI_FAIL, "Non-recoverable failure in name resolution" },
    { EAI_FAMILY, "ai_family not supported" },
    { EAI_MEMORY, "Memory allocation failure" },
    { EAI_NODATA, "No address associated with hostname" },
    { EAI_NONAME, "Name or service not known" },
    { EAI_SERVICE, "Servname not supported for ai_socktype" },
    { EAI_SOCKTYPE, "ai_socktype not supported" },
    { EAI_SYSTEM, "System error" }
  };

char *
gai_strerror (int code)
{
  size_t i;
  for (i = 0; i < sizeof (values) / sizeof (values[0]); ++i)
    if (values[i].code == code)
      return (char *) values[i].msg;

  return (char *) "Unknown error";
}

#endif /* !HAVE_GAI_STRERROR */
