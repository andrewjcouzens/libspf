/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  File:   util.c
*  Desc:   Utility functions
*
*  License:
*
*  The libspf Software License, Version 1.0
*
*  Copyright (c) 2004 James Couzens & Sean Comeau  All rights
*  reserved.
*
*  Redistribution and use in source and binary forms, with or without
*  modification, are permitted provided that the following conditions
*  are met:
*
*  1. Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*  2. Redistributions in binary form must reproduce the above copyright
*     notice, this list of conditions and the following disclaimer in
*     the documentation and/or other materials provided with the
*     distribution.
*
*  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
*  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
*  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
*  DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS MAKING USE OF THIS LICESEN
*  OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
*  USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
*  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
*  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
*  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
*  SUCH DAMAGE.
*
*/

#include "../../config.h"    /* autoconf */

#include "spf.h"             /* spf API */
#include "dns.h"             /* dns functions */
#include "macro.h"           /* our header */
#include "util.h"            /* utility functions */


/* MACRO_expand
*
*  Author: Sean Comeau <scomeau@obscurity.org>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:    01/18/04
*  Updated: 06/29/04 Roger Moser <Roger.Moser@pamho.net>
*
*  Desc:
*        Walks a string of macros tokenizing and expanding them along the
*  way, each token being inserted as a node into a linked list.  Once the
*  walk is complete the list is walked and the nodes are copied back out
*  in the order they were added as expanded macros into a string which is
*  then passed back to the calling function.
*
*  MACRO_freebuf is removed and I moved the code inside of this function since
*  before calling it, it was being walked anyway to copy out each string into
*  the return buffer, so now it just free's directly after and then destructs.
*
*/
char *MACRO_expand(peer_info_t *p, const char *s)
{
  const char * const macro_p = "%";     /* % (literal) */
  const char * const macro_d = "%20";   /* "URL" space */
  const char * const macro_u = " ";     /* whitespace */

  char *buf     = NULL;                 /* return buffer */
  char *ptr     = NULL;                 /* working pointer */
  char *cp      = NULL;                 /* working pointer */
  char *macro   = NULL;
  char *s_macro = NULL;                 /* single char macro */

  strbuf_t *master         = NULL;      /* list pointers */
  strbuf_node_t *c_node    = NULL;      /* c_node node */
  strbuf_node_t *kill_node = NULL;      /* temp node used in destruct */

  size_t len    = 0;                    /* leng of passed string */
  size_t i      = 0;                    /* index on a str */
  size_t length = 0;                    /* overall len of expanded str */


  if (s == NULL)
  {
    xepprintf("Passed a NULL string.  Abort!\n");
    return(NULL);
  }

  len = strlen(s);
  ptr = cp = xstrndup(s, (len + 1));

  master = xmalloc(SIZEOF(strbuf_t));
  master->head      = NULL;
  master->elements  = 0;

  while (*ptr)
  {
     /*
     * This works by moving through the string and replacing non-essential
     * elements with NULL chars until the character designating an expansion
     * mechanism is found.  The character is then sent off to MACRO_process
     * for expansion
    */
    if (*ptr == '%') /* start of macro */
    {
      switch (*(ptr + 1))
      {
        case '%':
        {
          /* convert %% into % */
          if (MACRO_addbuf(master, (char *)macro_p, 1) == SPF_FALSE)
          {
            xvprintf("Unable to allocate list node with (%c)!\n", macro_p);

            return(NULL);
          }

          ptr += 2;
          length++;

          break;
        } /* % */

        case '_':
        {
          /* convert %_ to a white space */
          if (MACRO_addbuf(master, (char *)macro_u, 1) == SPF_FALSE)
          {
            xvprintf("Unable to allocate list node with (%c)!\n", macro_u);

            return(NULL);
          }

          ptr += 2;
          length++;

          break;
        } /* - */

        case '-':
        {
          /* convert %- into URL encoded '%20' */
          if (MACRO_addbuf(master, (char *)macro_d, 3) == SPF_FALSE)
          {
            xvprintf("Unable to allocate list node with [%s]!\n", macro_d);

            return(NULL);
          }

          ptr    += 2;
          length += 3;

          break;
        } /* _ */

        case '{':
        {
          *ptr++ = '\0'; /* % */
          *ptr++ = '\0'; /* { */

          if ((i = UTIL_index(ptr, '}')) == 0)
          {
            xvprintf("'}' Invalid Macro (%c)\n", *(s + 1));

            return(NULL);  /* not closed, invalid macro */
          }

          *(ptr + i) = '\0'; /* } */

          xvprintf("Actual macro [%s]\n", ptr);
          if ((macro = MACRO_process(p, ptr, (i + 1))) == NULL)
          {
            xepprintf("macro process returned null!\n");
          }
          else
          {
            length += strlen(macro);
            xvprintf("Macro expanded to: [%s] %i bytes\n", macro,
              strlen(macro));

            if (MACRO_addbuf(master, macro, strlen(macro)) == SPF_FALSE)
            {
              xvprintf("Unable to allocate list node with [%s]!\n", macro);
              xfree(macro);

              return(NULL);  /* not closed, invalid macro */
            }
            xfree(macro);
          }
          ptr += i;

          break;
        } /* { */

        default:
        {
          xvprintf("ERROR: Invalid macro. [%s] Abort!\n", *(ptr + 1));

          /* need cleanup function call perhaps */
          return(NULL);
        } /* default */

      } /* switch */
    } /* if */
    else
    {
      if ((i = UTIL_index(ptr, '%')) == 0)
      {
        while (*(ptr + i))
        {
          i++;
        }
        s_macro = xmalloc(i + 1);
        memcpy(s_macro, ptr, (i + 1));
      }
      else
      {
        s_macro = xmalloc(i + 1);
        memcpy(s_macro, ptr, i);
      }

      length += i;

      if (MACRO_addbuf(master, s_macro, (i + 1)) == SPF_FALSE)
      {
        xvprintf("Unable to allocate list node with [%s]!\n", s_macro);

        return(NULL);
      }

      ptr += (i - 1);
      xvprintf("Freeing s_macro temp buf [%s]\n", s_macro);
      xfree(s_macro);
    }
    ptr++;
    xvprintf("Remaining buffer [%s]\n", ptr);
  } /* while */

  xprintf("Allocated %i bytes for return buf\n", length);
  buf = xmalloc(length + 1);

  c_node = master->head;
  while (c_node != NULL)
  {
    kill_node = c_node;

    if (kill_node->len > 1)
    {
      xvprintf("NODE: [%s] LEN: %i\n", kill_node->s, kill_node->len);
    }
    else
    {
      xvprintf("NODE: (%c) LEN: %i\n", kill_node->s, kill_node->len);
    }

    strncat(buf, kill_node->s, kill_node->len);
    xfree(kill_node->s);
    c_node = c_node->next;
    xfree(kill_node);
  }

  xfree(cp);
  xfree(master);

  xvprintf("Returning expanded macro: [%s]\n", buf);

  return(buf);
}


/* MACRO_process
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/21/04
*
*  Desc:
*         This function takes a NULL terminated string containing only one
*  macro. It returns a new string containing whatever that macro expanded to.
*  Returns NULL if the macro can not be expanded.
*
*  exists:%{ir}.%{l1r+-}._spf.%{d}
*
*  Date:   08/??/04 - Travis Anderson <tanderson@codeshare.ca>
*
*  Desc:
*          Fixed problematic 'p' macro with the addition of new DNS function
*  DNS_check_client_reverse.
*
*  Date:   09/11/04 - James Couzens <jcouzens@codeshare.ca>
*
*  Desc:
*          Removed strlen calls originally intended for replacement
*  with either a generic limit (SPF_MAX_STR), or a more stringent limit safely
*  imposed upon the malloc.
*    
*
*/
char *MACRO_process(peer_info_t *p, char *macro, const size_t size)
{
  int c = 0;                /* stores a lower case version of the macro if necessary */

  size_t i = 0;             /* utility for string lengths */

  char *rev_addr = NULL;    /* used by p macro */


  if (macro == NULL)
  {
    xepprintf("Passed a NULL string.  Abort!\n");

    return(SPF_FALSE);
  }

  xprintf("called with [%s] and len: %i\n", macro, size);

  rev_addr = NULL;
  i = 0;

  if (isupper(*macro))
  {
    c = tolower(*macro);
  }
  else
  {
    c = *macro;
  }

  switch (c)
  {
    /* current-domain */
    case 'd':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->current_domain));
      }
      else
      {
        xvprintf("macro 'd' expands to: [%s]\n", p->current_domain);

        return(xstrndup(p->current_domain, SPF_MAX_STR));
      }
    } /* 'd' */

    /* HELO/EHLO domain */
    case 'h':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->helo));
      }
      else
      {
        xvprintf("macro 'h' expands to: [%s]\n", p->helo);

        if (p->helo != NULL)
        {
          return(xstrndup(p->helo, SPF_MAX_ENV_HELO));
        }
        else
        {
          return(xstrndup(p->ehlo, SPF_MAX_ENV_HELO));
        }
      }
    } /* 'h' */

    /* SMTP client IP (nibble format when an IPv6 address) */
    case 'i':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->r_ip));
      }
      else
      {
        xvprintf("macro 'i' expands to: [%s]\n", p->r_ip);

        return(xstrndup(p->r_ip, SPF_MAX_IP_ADDR));
      }
    } /* 'i' */

    /* local-part of responsible-sender */
    case 'l':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->local_part));
      }
      else
      {
        xvprintf("macro 'l' expands to: [%s]\n", p->local_part);

        return(xstrndup(p->local_part, SPF_MAX_LOCAL_PART));
      }
    } /* 'l' */

    /* responsible domain */
    case 'o':
     /*
     * Comment by: James Couzens <jcouzens@codeshare.ca>
     * Date:       01/02/05
     *
     * Michael Elliott <elliott@rod.msen.com> correctly pointed out to me that 
     * this is failing because during recursion it points to the current 
     * domain instead of as per RFC requirements, that it do not change during
     * any form of recursion.  p->original_domain was added to deal with this
     * properly. 
    */
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->original_domain));
      }
      else
      {
        xvprintf("macro 'o' expands to: [%s]\n", p->original_domain);

        return(xstrndup(p->original_domain, SPF_MAX_STR));
      }
    } /* 'o' */ 

    /* SMTP client domain name */
    case 'p':
    {
      if (DNS_check_client_reverse(p) == SPF_FALSE)
      {
        p->r_vhname = xmalloc(8);
        snprintf(p->r_vhname, 8, "unknown");
      }

      if (*(macro + 1))
      {
        xvprintf("macro '%c' expands to: [%s]\n", c, p->r_vhname);

        return(MACRO_eatmore(macro, p->r_vhname));
      }
      else
      {
        xvprintf("macro '%c' expands to: [%s]\n", c, p->r_vhname);

        return(xstrndup(p->r_vhname, SPF_MAX_STR));
      }
    } /* 'p' */

    /* responsible sender*/
    case 's':
    {
      if ((p->cur_eaddr != NULL) || p->cur_eaddr)
      {
        xfree(p->cur_eaddr);
      }

      xprintf("local-part: [%s]; current domain: [%s]\n",
        p->local_part, p->original_domain);

      i = ((strlen(p->local_part) + strlen(p->original_domain) + 2));
      p->cur_eaddr = xmalloc(i);

      snprintf(p->cur_eaddr, i, "%s@%s", p->local_part, p->original_domain);

      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->cur_eaddr));
      }
      else
      {
        xvprintf("macro 's' expands to: [%s]\n", p->cur_eaddr);

        return(xstrndup(p->cur_eaddr, SPF_MAX_STR));
      }
    } /* 's' */

    /* current timestamp in UTC epoch seconds notation */
    case 't':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->utc_time));
      }
      else
      {
        xvprintf("macro 't' expands to: [%s]\n", p->utc_time);

        return(xstrndup(p->utc_time, SPF_MAX_UTC_TIME));
      }
    } /* 't' */

    /* client IP version string: "in-addr" for ipv4 or "ip6" for ipv6 */
    case 'v':
    {
      if (*(macro + 1))
      {
        return(MACRO_eatmore(macro, p->ip_ver));
      }
      else
      {
        xvprintf("macro 'v' expands to: [%s]\n", p->ip_ver);
        return(xstrndup(p->ip_ver, SPF_MAX_IP_ADDR));
      }
    } /* 'v' */

    /* sekret */
    case 'x':
    {
      if (size > 1)
      {
        if (*(macro + 1) == 'R' || *(macro + 1) == 'r')
        {
          return(xstrndup(p->mta_hname, SPF_MAX_HNAME));
        }
      }
      break;
    } /* 'x' */

    default:
    {
      return(xstrndup(macro, SPF_MAX_STR));
    } /* default */

  } /* switch */

  return(NULL);
}


/* MACRO_eatmore
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/22/04
*  Date:   07/02/04 James Couzens <jcouzens@codeshare.ca> (compiler warnings)
*
*  Desc:
*         This function is called whenever a macro is more than one character
*  long and so we have to 'eatmore' ;-)  macro is the unexpanded macro and
*  s is the expanded string of the original macro would have been returned as
*  had it been single.  Returns the expanded macro using dynamically allocated
*  memory upon success and in the process will FREE s after allocating more
*  memory (if necessary) and copying it over.  Returns NULL upon failure.
*
*/
char *MACRO_eatmore(char *macro, char *s)
{
  size_t i = 0;               /* how much of the buffer we are using */

  char delim = '\0';          /* marco is a delimiter modifier */

  char *cp      = NULL;       /* working pointer */
  char *buf     = NULL;       /* return buffer */
  char *rev_str = NULL;       /* temporary buffer */
  char *d_buf   = NULL;       /* temporary buffer */

  u_int8_t n_dot = 0;         /* number of 'delimiter' items in a string */
  u_int8_t rev   = 0;         /* string to be reversed */
  u_int8_t digit = 0;         /* macro is a digit modifier */


  if (macro == NULL)
  {
    xepprintf("Passed a NULL string.  Abort!\n");

    return(NULL);
  }

  xprintf("Called with macro [%s] and string [%s]\n", macro, s);

  /* need a proper value for this not just SPF_MAX_MACRO need to know the MAXIMUM
   * expandable length of a macro. */

  cp    = macro;
  delim = '.';

  while (*cp)
  {
    if (isdigit(*cp))
    {
      digit = atoi(cp);
    }
    else if (UTIL_is_spf_delim(*cp) == SPF_TRUE)
    {
      delim = *cp;
    }
    else if ((*cp == 'r') || (*cp == 'R'))
    {
      rev = 1;
    }
    cp++;
  }

  xvprintf("mac:[%s] r:(%i) dig:(%i) dlm: (%c)\n",
    macro, rev, digit, delim);

  i = 0;
  /* reverse the string */
  if (rev == 1)
  {
    /*delim = '.';*/
    rev_str = UTIL_reverse(s, delim);
    s = NULL;
  }

  if (s == NULL)
  {
    cp = rev_str;
  }
  else
  {
    cp = s;
  }

  /* exercise digit modifier on string */
  if (digit > 0)
  {
    n_dot = UTIL_count_delim(cp, delim);

    if (digit > n_dot)
    {
      digit = n_dot;
    }

    if ((d_buf = UTIL_split_strr(cp, delim, digit)) != NULL)
    {
      i = strlen(d_buf);
    }
    else
    {
      d_buf = cp;
      i = strlen(d_buf);
    }

    buf = xmalloc(i + 1);
    memcpy(buf, d_buf, (i + 1));

    if (d_buf != cp)
    {
      xfree(d_buf);
    }
  }
  else if (rev == 1)
  {
    buf = xstrndup(rev_str, SPF_MAX_MACRO);
  }

  xvprintf("Returning [%s] (%i bytes)\n", buf, strlen(buf));

  if (rev == 1)
  {
    xfree(rev_str);
  }

  return(buf);
}


/* MACRO_addbuf
*
*  Author: Sean Comeau <scomeau@obscurity.org>
*  Author: James Couznes <jcouzens@codeshare.ca>
*
*  Date:    01/18/04
*  Updated: 01/24/04
*
*
*  Desc:
*         Appends nodes to a master list which is passed of type
*  strbuf_t.  The nodes are of type strbuf_node_t and appended on
*  the end and the list is reordered to reflect this.  Returns
*  SPF_TRUE upon success and SPF_FALSE
*  upon failure.
*
*/
SPF_BOOL MACRO_addbuf(strbuf_t *master, char *s, size_t size)
{
  strbuf_node_t *c_node     = NULL;  /* c_node working node */
  strbuf_node_t *new_node   = NULL;  /* newly allocated node */
  strbuf_node_t *prev_node  = NULL;  /* previous working node */


  if (s == NULL)
  {
    xepprintf("Passed a NULL string.  Abort!\n");

    return(SPF_FALSE);
  }

  xvprintf("Called with [%s] %i (%i) bytes.\n", s, size, strlen(s));

  new_node    = xmalloc(SIZEOF(strbuf_node_t));
  new_node->s = xmalloc(size + 1);

  strncpy(new_node->s, s, size);
  new_node->len   = size;
  new_node->next  = NULL;

  xvprintf("Added [%s] to node of len: %i)\n", new_node->s,
    new_node->len);

  prev_node = NULL;
  c_node    = master->head;

  /* reorder the list with the NEW element on the end */
  while (c_node != NULL)
  {
    prev_node = c_node;
    c_node    = c_node->next;
  }

  if (prev_node != NULL)
  {
    new_node->next  = prev_node->next;
    prev_node->next = new_node;
  }
  else
  {
    master->head = new_node;
  }

  master->elements++;

  return(SPF_TRUE);
}

/* end macro.c */

