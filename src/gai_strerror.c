/*  Copyright (C) 1997, 1999, 2002, 2007 Free Software Foundation, Inc.

    This file is part of jwhois

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

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(s)  gettext(s)
#else
# define _(s)  (s)
#endif

#ifndef HAVE_GAI_STRERROR

/* Error values for `getaddrinfo' function.  */
# define EAI_BADFLAGS	-1	/* Invalid value for `ai_flags' field.  */
# define EAI_NONAME	-2	/* NAME or SERVICE is unknown.  */
# define EAI_AGAIN	-3	/* Temporary failure in name resolution.  */
# define EAI_FAIL	-4	/* Non-recoverable failure in name res.  */
# define EAI_NODATA	-5	/* No address associated with NAME.  */
# define EAI_FAMILY	-6	/* `ai_family' not supported.  */
# define EAI_SOCKTYPE	-7	/* `ai_socktype' not supported.  */
# define EAI_SERVICE	-8	/* SERVICE not supported for `ai_socktype'.  */
# define EAI_ADDRFAMILY	-9	/* Address family for NAME not supported.  */
# define EAI_MEMORY	-10	/* Memory allocation failure.  */
# define EAI_SYSTEM	-11	/* System error returned in `errno'.  */

const char *
gai_strerror (int code)
{
  size_t i;
  switch(code)
    {
    case EAI_ADDRFAMILY:
      return (char *) _("Address family for hostname not supported");
    case EAI_AGAIN:
      return (char *) _("Temporary failure in name resolution");
    case EAI_BADFLAGS:
      return (char *) _("Bad value for ai_flags");
    case EAI_FAIL:
      return (char *) _("Non-recoverable failure in name resolution");
    case EAI_FAMILY:
      return (char *) _("ai_family not supported");
    case EAI_MEMORY:
      return (char *) _("Memory allocation failure");
    case EAI_NODATA:
      return (char *) _("No address associated with hostname");
    case EAI_NONAME:
      return (char *) _("Name or service not known");
    case EAI_SERVICE:
      return (char *) _("Servname not supported for ai_socktype");
    case EAI_SOCKTYPE:
      return (char *) _("ai_socktype not supported");
    case EAI_SYSTEM:
      return (char *) _("System error");
    default:
      return (char *) _("Unknown error");
    }
}

#endif /* !HAVE_GAI_STRERROR */
