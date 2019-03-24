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


#include "../../config.h"

#ifdef _WITH_PTHREADS
#include <pthread.h>          /* pthread_mutex_t */
#endif /* _WITH_PTHREADS */

#include "util.h"             /* Utility functions */
#include "dns.h"              /* DNS Functions */

#undef  VERSION               /* autoconf */


#ifdef _WITH_PTHREADS
 /*
 * pthread mutex used to facilitate reentrant competence within the
 * utility functions (generally the debugging functionality, you
 * could (after some poking around) probably safely remove this if
 * debugging was disabled)
*/
pthread_mutex_t util_mutex;

#else
/* utility functions dummy pthread mutex wrapper */
void *util_mutex = NULL;

#endif /* _WITH_PTHREADS */



 /*
 * globals
 *
*/

extern int errno;



/* _pprintf_dbg
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   09/08/04
*
*  Desc:
*          Handles debugging output when no variadic macro's are desired
*  and the caller simply wishes to send a single string to output but
*  wishes to have the appropriate function and other identifiers
*  prepended.
*
*          Referenced by xpprintf (formerly used for profile output)
*  and xepprintf.
*
*/
void _pprintf_dbg(u_int8_t level, const char *func, const char *file,
  const size_t line, const char *s)
{
#ifdef _SPF_DEBUG_LOGFILE
  FILE     *fp      = NULL;    /* file pointer */
  #endif /* _SPF_DEBUG_LOGFILE */

  char *buf = NULL;           /* working buffer */


  if (!s)
  {
    fprintf(stderr, "_eprintf_dbg passed a NULL string\n");
    fflush(stderr);

    return;
  }

  buf = xmalloc(SPF_MAX_DEBUG + 1);
  snprintf(buf, SPF_MAX_DEBUG,
    "[%s :: %s->%zu]; %s", func, file, line, s);

  if (f_bit_set(confg.level, level))
  {
    if (level == FL_D)          /* xpprintf */
    {
#ifndef _SPF_DEBUG_LOGFILE
      fprintf(stdout, "%s", buf);
      fflush(stdout);
#else
      if ((fp = fopen(DEBUG_LOG_FILE, "a")) != NULL)
      {
        fprintf(fp, "%s", buf);
        fclose(fp);
      }
      else
      {
        fprintf(stderr, "libSPF can't open file [%s] for writing!\n",
          DEBUG_LOG_FILE);

        fflush(stderr);
        perror(func);
      }
#endif /* _SPF_DEBUG_LOGFILE */
    }
  }

  if (level == FL_F)           /* xepprintf */
  { 
    fprintf(stderr, "%s", buf);
    fflush(stderr);
  }

  xfree(buf);  

  return;
}


/* _printf_dbg
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/25/03
*  Date:   02/18/04 (updated)
*
*  Desc:
*          Tied to a compile time switch this can instantly and at little
*  to no real expense enable a discreet debugging with out hoards of
*  #ifdefs all over the place.
*
*  Date:   09/08/04 - James Couzens <jcouzens@codeshare.ca>
*
*  Desc:
*          Modified to handle output for xeprintf (behaviour adjusted to call
*  here instead) so that its actually clear where errors are being raised from.
*
*/
void _printf_dbg(u_int8_t level, const char *func, const char *file,
  const size_t line, const char *format,...)
{
#ifdef _SPF_DEBUG_LOGFILE
  FILE *fp = NULL;      /* file pointer */
#endif /* _SPF_DEBUG_LOGFILE */

  char *buf  = NULL;    /* working buffer */
  char *tbuf = NULL;    /* working buffer for eprintf */

  va_list argptr;       /* pointer to current argument from array */


  xpthread_mutex_lock(&util_mutex);

  if (!format || *format == '\0')
  {
    fprintf(stderr, "_printf_dbg passed null format array\n");
    fflush(stderr);

    return;
  }

  buf  = xmalloc(SPF_MAX_DEBUG + 1);
  tbuf = xmalloc(SPF_MAX_DEBUG * 2);

  va_start(argptr, format);
  vsnprintf(buf, SPF_MAX_DEBUG, format, argptr);
  va_end(argptr);

  snprintf(tbuf, (SPF_MAX_DEBUG * 2),
    "[%s :: %s->%zu]; %s", func, file, line, buf);

  /* xepprintf */
  if (level == FL_E)
  {
    fprintf(stderr, "%s", tbuf);
    fflush(stderr);
  }
  else
  {
    if (f_bit_set(confg.level, level))
    {
#ifndef _SPF_DEBUG_LOGFILE
      fprintf(stdout, tbuf);
      fflush(stdout);
#else
      if ((fp = fopen(DEBUG_LOG_FILE, "a")) != NULL)
      {
        fprintf(fp, "[%s :: %s->%i]; %s", func, file, line, buf);
        fclose(fp);
      }
      else
      {
        fprintf(stderr, "libSPF can't open file [%s] for writing!\n",
          DEBUG_LOG_FILE);

        fflush(stderr);
        perror(func);
      }
#endif /* _SPF_DEBUG_LOGFILE */
    }
  } /* else */

  free(buf);
  free(tbuf);

  xpthread_mutex_unlock(&util_mutex);

  return;
}


#ifndef _SPF_DEBUG_LOGFILE
/* dummy_debug
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/25/03
*
*  Desc:
*          dummy function thats used instead of the _printf_dbg function
*  when compiling without debugging
*
*/
void _dummy_debug(const u_int8_t level, const char *func, const char *file,
  const size_t line, const char *format,...)
{
  return;
}


/* dummy_debug
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*     
*  Date:   12/25/03
*     
*  Desc:
*          dummy function thats used instead of the _printf_dbg function
*  when compiling without debugging
*       
*/ 
void _dummy_pdebug(const u_int8_t level, const char *func, const char *file,
  const size_t line, const char *s)
{
  return;
}     

#endif


/* UTIL_get_date
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Date:   Sun Jan 18 06:02:13 PST 2004
*
*  Desc:
*          Returns in a buffer that must be freed by the caller, the date
*  in the format YY-MM-DD HH:MM:SS and is derived from UTC time.
*
*  Date:   09/08/04 - James Couzens <jcouzens@codeshare.ca>
*
*  Desc:
*          Added pthread mutex lock during body of this function because it
*  appears as those inspite of the use of localtime_r there is some un-safe
*  behaviour that goes on here so for now the mutex here appears to solve
*  the problem.
*
*/
char *UTIL_get_date(void)
{
  struct tm *now  = NULL;    /* time in tm struct format  */
  struct tm tmbuf = {0};     /* reentrant buffer for localtime_r */

  time_t curtime  = {0};     /* current time time_t struct format */

  char *my_time   = NULL;    /* time in human readable format */


  xpthread_mutex_lock(&util_mutex);

  curtime = time(NULL);
  now     = localtime_r(&curtime, &tmbuf);
  my_time = xmalloc(SPF_MAX_DATETIME);

  strftime(my_time, SPF_MAX_DATETIME, "%Y-%m-%d %H:%M:%S ", now);
  my_time[(SPF_MAX_DATETIME - 1)] = '\0';

  xpthread_mutex_unlock(&util_mutex);

  return(my_time);
}


/* UTIL_log_result
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   02/04/04
*
*  Desc:
*          Tied to a compile time switch this can instantly and at little
*  to no real expense enable a discreet debugging with out hoards of
*  #ifdefs all over the place.
*
*  Date:   09/08/04 - James Couzens <jcouzens@codeshare.ca>
*
*  Desc:
*          Added pthread mutex lock during body of this function because it
*  is to the detriment of stability to have multiple threads attempting to
*  open/write/close the same file at the same time!  :-)
*
*/
void UTIL_log_result(peer_info_t *p)
{
  FILE *fp   = NULL;    /* file pointer */

  char *buf  = NULL;    /* working buffer */
  char *date = NULL;    /* date/time stamp */


  date = UTIL_get_date();
  buf  = xmalloc(SPF_MAX_DEBUG);
  *(date + (strlen(date) - 1)) = '\0';

  if (p->spf_ver == 0)
  {
    p->spf_ver = SPF_VERSION;
  }

  xpthread_mutex_lock(&util_mutex);

  snprintf(buf, SPF_MAX_DEBUG,
    "[%s] result: %s :: %s [%s], ver: %i, depth: %i, error: [%s]\n",
    date, p->spf_result[p->RES].s, p->from,
    p->r_ip, p->spf_rlevel, p->spf_ver, p->error);

  if ((fp = fopen(OUTPUT_LOG_FILE, "a")) != NULL)
  {
    fprintf(fp, "%s", buf);
    fclose(fp);
  }

  xpthread_mutex_unlock(&util_mutex);

  xfree(date);
  xfree(buf);

  return;
}


/* UTIL_strndup
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/25/03
*
*  Desc:
*          n bytes are allocated and then filled with \0 chars.  Char s
*  is copied over to the allocated memory writing n -1 bytes leaving the
*  new string NULL terminated.  This new string is returned upon success
*  and NULL upon failure.
*
*/
char *UTIL_strndup(const char *s, const size_t n)
{
  size_t i = 0;            /* length of s */
  
  char *ret_ptr = NULL;    /* return buffer */


  if (!s || (n <= 0))
  {
    xvprintf("[%i] Passed string is NULL.  Abort!.\n", i);

    return(NULL);
  }

  xvprintf("called with string: [%s] of len: %i\n", s, n);
  
  if ((i = (strlen(s) + 1)) > n)
  {
    ret_ptr = xmalloc(n);
    xvprintf("Allocated %u bytes of memory.\n", n);
    memcpy(ret_ptr, s, (n - 1));
  }
  else
  {
    ret_ptr = xmalloc(i);
    xvprintf("Allocated %u bytes of memory.\n", i);
    memcpy(ret_ptr, s, (i - 1));
  }
    
  xvprintf("leaving func; returning string: [%s]\n", ret_ptr);

  return(ret_ptr);
}


/* xstrdup
*
*  Author: Patrick Earl (http://patearl.net/)
*          Adapted from xstrndup()
*
*  Date:   02/04/04
*
*  Desc:
*          strlen(s)+1 bytes are allocated and s is copied into the
* freshly allocated memory.  If the allocation or copy fails, NULL
* NULL will be returned.
*
*/
char *UTIL_strdup(const char *s)
{
  char *ret_ptr = NULL;    /* return buffer */


  if (s == NULL)
  {
    xepprintf("Passed string is NULL.  Abort!.\n");

    return(NULL);
  }

  if ((ret_ptr = strdup(s)) == NULL)
  {
    xepprintf("Unable to allocate memory\n");
  }

  xvprintf("leaving func; returning string: [%s]\n", ret_ptr);

  return(ret_ptr);
}


/* UTIL_malloc
*
*  Author: Travis Anderson <travis@anthrax.ca>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   02/17/04
*
*  Desc:
*         Wrapper for malloc.  Upon success, behaves as malloc does.
*  Wrapper functionality is to print an error message and exit upon failure.
*
*/
void *UTIL_malloc(const int32_t n, const char *file, int32_t line,
  const char *func)
{
  void *x = malloc(n);

  if (x == NULL)
  {
    xvprintf("Unable to allocate %i bytes at %s:%i in %s\n",
      n, file, line, func);

    /*
     * Be advised this is the only place I do this, because quite
     * honestly, if this library can't get a few bytes of memory,
     * your mailserver segfaulting as a result of this exit, or 
     * quitting or whatever is the LEAST of your problems! - James
    */
    exit(0);
  }

#ifdef _WITH_PARANOID_MALLOC
  memset(x, '\0', n);
#endif /* _WITH_PARANOID_MALLOC */

  return(x);
}


/* UTIL_realloc
*
*  Author: Travis Anderson <travis@anthrax.ca>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   02/17/04
*
*  Desc:
*         Wrapper for realloc.  If 'p' is NULL, allocates memory via a call to
*  UTIL_malloc, otherwise if 'x' is assigned successfully, the behaviour is
*  identical to realloc.  Wrapper functionality is to print an error message
*  and exit upon failure.
*
*/
void *UTIL_realloc(void *p, const int32_t n, const char *file,
  const int32_t line, const char *func)
{
  void *x = NULL;  /* working pointer */


  if (p == NULL)
  {
    return(UTIL_malloc(n, file, line, func));
  }

  x = realloc(p, n);
  if (x == NULL)
  {
    xvprintf("Unable to reallocate %i bytes at %s:%i in %s; " \
      "original address 0x%x\n", n, file, line, func, (uintptr_t)p);

     exit(0);
  }
 
  return(x);
}


/* UTIL_free
*
*  Author: Travis Anderson <travis@anthrax.ca>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   02/17/04
*
*  Desc:
*         Wrapper for free.  Upon success, behaves as free does.
*  Wrapper functionality is to print an error message and exit upon
*  failure.
*
*/
void UTIL_free(void *p, const char *file, const int32_t line, const char *func)
{
  if (p == NULL)
  {
    xvprintf("Unable to free() on NULL pointer at %s:%i in %s; " \
      "address 0x%x.\n", file, line, func, (uintptr_t)p);

    return;
  }

  xvprintf("Free address 0x%x by %s on line %i [%s]\n",
    (uintptr_t)p, func, line, file);

  free(p);

  return;
}


/* UTIL_index
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/19/03
*
*  Desc:
*          s is walked until c is found, at which time i is returned
*  which is the number of bytes from the left it walked until c was
*  found (not including c its self);
*
*  Date:   09/01/04 - Roger Moser
*
*  Desc:
*          The return upon an error (s being NULL for exmaple) is now
*  -1 because returning 0 was really ambiguous.
*
*  Returns: -1 upon error
*  Returns: 0 upon no match
*  Returns: > 0 upon success which is the number of bytes from the left
*           the string was walked until 'c' was found.
*
*/
int16_t UTIL_index(const char *s, const char c)
{
  int16_t i = 0;     /* utility */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(-1);
  }

  xvprintf("called with string: [%s]; char: %c\n", s, c);

  i = 0;
  while (*s)
  {
    if (*s == c)
    {
      xvprintf("Found search char: (%c); Returning: (%i)\n", *s, i);

      return(i);
    }
    i++;
    s++;
  }

  xpprintf("leaving func\n");

  return(0);
}


/* UTIL_split_str
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/21/04
*
*  Desc:
*          s is walked through to find 'delim' until it finds 'delim'
*  num times.  Upon final match it returns the remainder of the string
*  in a newly allocated buffer.  Upon failure returns NULL.
*
*  Date:   09/01/04 - Roger Moser
* 
*  Desc:
*          'cp' was not being freed upon exiting the function when 'c'
*  was not found within the string.
*
*/
char *UTIL_split_str(const char *s, const char c, const u_int8_t num)
{
  u_int8_t i = 0;       /* utility */

  char *cp  = NULL;     /* copy buffer of s */
  char *p   = NULL;     /* pointer to copy */
  char *ret = NULL;     /* return buffer */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(NULL);
  }

  xvprintf("called with string: [%s]; char (%c); int: (%i)\n",
    s, c, num);

  p = cp = xstrndup(s, SPF_MAX_STR);

  i = 0;
  while(*p)
  {
    if (*p == c)
    {
      i++;
      if (i == num)
      {
        p++;
        ret = xstrndup(p, SPF_MAX_STR);

        xfree(cp);

        xvprintf("returning: %s\n", ret);

        return(ret);
      }
    }
    p++;
  }

  xfree(cp);
  xvprintf("[%i] returning NULL\n", i);

  return(NULL);
}


/* UTIL_split_strr
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/30/04
*
*  Desc:
*          s is walked to the end of its self, and then is walked back
*  towards the beginning of the string until it has found 'c' the
*  delimiter, 'num' times.  Upon success memory is allocated and the
*  remainder of s is returned.  Upon failure NULL is returned.
*
*  Date:    09/01/04 - Roger Moser
*
*  Desc:
*           Replaced 'p = (char *)&(s[strlen(s) - 1]);' with a more
*  optimized 'p = strchr(s, '\0') - 1;'.  Also applied a fix so that
*  the function properly returns NULL when 's' is an empty string.
*
*/
char *UTIL_split_strr(const char *s, const char c, const u_int8_t num)
{
  u_int8_t i = 0;      /* number of times delim (c) is found */

  char *p   = NULL;    /* pointer to the last character of s before the \0 */
  char *ret = NULL;    /* return buffer */


  if ((s == NULL) || (*s == '\0'))
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(NULL);
  }

  xvprintf("called with [%s]\n", s);


  /* assign 'p' to the last char before the null termination of 's'*/
  /*p = (char *)&(s[strlen(s) - 1]);*/
  p = (strchr(s, '\0') - 1);

  i = 0;
  while(p != s)
  {
    if (*p == c)
    {
      i++;
      if (i == num)
      {
        if (*p == '.')
        {
          p++; /* don't want that period */
        }

        ret = xstrdup(p);

        xvprintf("delimiter found (%i) times; returning [%s].\n", i, ret);

        return(ret);
      }
    }
    p--;
  }

  xvprintf("delimiter (%c) found (%u) times; returing NULL\n", c, i);

  return(NULL);
}


/* UTIL_count_delim
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/21/04
*
*  Desc:
*          s is walked through and each time 'delim' is found a counter is 
*  incremented and once complete, that integer is returned to the calling 
*  function.  Specifically for the purposes of this project i is limited by its
*  type to 255.
*
*  Returns: > 0 && <= 255 upon success
*  Returns: 0 upon failure
*
*/
u_int8_t UTIL_count_delim(const char *s, const char c)
{
  u_int8_t i = 0;    /* utility */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(0);
  }

  while (*s && i < SPF_MAX_DELIM)
  {
    if (*s == c)
    {
      i++;
    }
    s++;
  }

  xvprintf("found (%i) number of delimiters; returning.\n", i);

  return(i);
}


/* UTIL_is_spf_delim
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/21/04
*
*  Desc:
*          c is compared against all the valid spf delimiters and
*  in the case of a SPF_PASS, the function returns true, otherwise it will
*  return false.
*
*/
SPF_BOOL UTIL_is_spf_delim(const char c)
{
  if (!c)
  {
    xepprintf("called with a NULL char!  Aborting check.\n");
  
    return(SPF_FALSE);
  }

  xvprintf("called with char (%c)\n", c);

  if (c == '.' ||
      c == '-' ||
      c == '+' ||
      c == ',' ||
      c == '|' ||
      c == '_')
  {
    xpprintf("leaving func; returning SPF_FALSE\n");

    return(SPF_TRUE);
  }

  xpprintf("leaving func; returning SPF_FALSE\n");

  return(SPF_FALSE);
}


/* UTIL_is_spf_result
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/27/04
*
*  Desc:
*          c is compared against all the valid spf prefixes and
*  will return SPF_TRUE in the event one is found.  Returns SPF_FALSE
*  when no valid prefix is found or c is empty.
*
*/
SPF_BOOL UTIL_is_spf_result(const char c)
{
  if (!c)
  {
    xpprintf("passed a NULL or empty char!\n");

    return(SPF_FALSE);
  }

  xvprintf("called with char (%c)\n", c);

  if (c == '+' || c == '-' || c == '~' || c == '?')
  {
    xpprintf("leaving func; returning SPF_TRUE\n");

    return(SPF_TRUE);
  }

  xpprintf("leaving func; returning SPF_FALSE\n");

  return(SPF_FALSE);
}


/* UTIL_is_macro
*
*  Author:  James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/30/04
*
*  Desc:
*          s is walked through in search of a macro which consist of
*  %{?}, ? being an SPF_UNKNOWN number of chars in between.  An instance of
*  a macro is searched for.  Upon success SPF_TRUE is returned.  Upon failure
*  to find a macro, SPF_FALSE is returned.
*
*/
SPF_BOOL UTIL_is_macro(const char *s)
{
  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(SPF_FALSE);
  }

  xvprintf("called with string [%s]\n", s);

  while (*s++)
  {
    if ((*s == '%') && (*(s + 1) == '{'))
    {
      if (strstr(s, "}"))
      {
        xpprintf("leaving func; returning SPF_TRUE\n");

        return(SPF_TRUE);
      }
    }
  }

  xpprintf("leaving func; returning SPF_FALSE\n");

  return(SPF_FALSE);
}


/* UTIL_mx_cmp
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/02/04
*
*  Desc:
*          Using the domain name found in the passed peer_info
*  structure, the associated T_MX records are looked up and then their
*  respective hostnames resolved (if they happen to be IP addresses the
*  resolver library takes care of this. <3).  Each IP is compared
*  against the remote peer's IP (from peer_info).  Upon success returns
*  SPF_TRUE, upon failure returns SPF_FALSE.
*
*/
SPF_BOOL UTIL_mx_cmp(peer_info_t *p, const char *s, const int8_t cidr)
{
  SPF_BOOL MX_SPF_MATCH;       /* true / false */

  char *rr_data   = NULL;     /* record */
  char *token     = NULL;     /* token for splitting records */
  char *token_ptr = NULL;     /* working pointer when tokenizing */
  char *peer_ip   = NULL;     /* remote host converted to string */


  MX_SPF_MATCH = SPF_FALSE;
  
  token_ptr = rr_data;

  if ((rr_data = DNS_query(p, s, T_MX, NULL)) == NULL)
  {
    xpprintf("SPF_ERROR parsing DNS Query\n");

    return(SPF_FALSE);
  }

  xvprintf("rr_data is: [%s]\n", rr_data);

  peer_ip = xstrndup(inet_ntoa(p->addr), 16);
  token   = strtok_r(rr_data, " ", &token_ptr);

  while (token != NULL)
  {
    xvprintf("TOKEN: [%s]\n", token);

    if (UTIL_validate_hostname(p, token, cidr) == SPF_TRUE)
    {
      xvprintf("%s validated via [%s]\n", p->from, token);

      MX_SPF_MATCH = SPF_TRUE;
      UTIL_assoc_prefix(p, SPF_PASS, NULL);
      token = NULL;
    }
    else
    {
      token = strtok_r(NULL, " ", &token_ptr);
    }
  }

  xfree(peer_ip);
  xfree(rr_data);

  return(MX_SPF_MATCH);
}


/* UTIL_a_cmp
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/02/04
*
*  Desc:
*          Calls gethostbyname to grab all records associated with a the
*  hostname contained within s.  On success returns SPF_TRUE, on SPF_ERROR
*  returns SPF_FALSE.
*
*  Note:
*          We need to define and set a limit on the number of recursive
*  lookups.  I recall seeing this in the RFC, we should discuss this.
*
*/
SPF_BOOL UTIL_a_cmp(peer_info_t *p, const char *s, const int8_t cidr)
{
  int16_t pos = 0;                    /* position in DNS packet */

  int tmp_errno = 0;                  /* temporary errno placeholder */

  size_t s_len = 0;                   /* length of s (hostname) */

  char *rr_data   = NULL;             /* data storage for DNS query */
  char *token_ptr = NULL;             /* token pointer */
  char *gbuf      = NULL;             /* buf for reentrant gethostbyname call */
  char *copy      = NULL;             /* copy of s */
  char *cp        = NULL;             /* pointer to copy of s */

  char **a;                           /**/

  struct hostent *hp    = NULL;       /* hostent structure */
  struct hostent tmp_hp = {0};        /* temporary hostent (xgethostbyname) */

  policy_addr_t policy_addr = {0};    /* used during CIDR comparisons */


  if (s == NULL)
  {
    xepprintf("Passed string is NULL.  Abort!.\n");

    return(SPF_FALSE);
  }

  xvprintf("called with [%s] and cidr: %i\n", s, cidr);

  gbuf      = xmalloc(SPF_MAX_GHBNR_DBUF);
  s_len     = strlen(s);
  token_ptr = rr_data;

  /* we're dealing with a:some.hostname/cidr */
  if ((s_len > 1) && (*(s + 1) == ':'))
  {
    cp = copy = xstrndup(s, (s_len + 1));

    if (cidr != 32)
    {
      /* We don't want a netmask, so lets remove it */
      cp[s_len - 3] = '\0';
    }

    if ((pos = UTIL_index(cp, ':')) <= 0)
    {
      xeprintf("ERROR parsing passed mechanism token [%s]\n", cp);

      xfree(copy);
      xfree(gbuf);

      return(SPF_FALSE);
    }

    /* move passed the mechanism text */
    cp += (pos + 1);
  }
  else
  {
    cp = copy = xstrndup(p->current_domain, SPF_MAX_HNAME);
  }

  if ((hp = xgethostbyname(cp, &tmp_hp, gbuf, SPF_MAX_GHBNR_DBUF,
    &tmp_errno)) != NULL)
  {
    for (a = hp->h_addr_list; *a; a++)
    {
      memcpy(&policy_addr.addr.s_addr, *a, SIZEOF(struct in_addr));

      xvprintf("IN ADDR; Checking: %lu\n", policy_addr.addr.s_addr);

      /* cidr is assumed checked by the calling function! */
      policy_addr.cidr = cidr;

      if (UTIL_cidr_cmp(&policy_addr, &p->addr) == SPF_TRUE)
      {
        *a = NULL;

        UTIL_assoc_prefix(p, SPF_PASS, NULL);

        xfree(copy);
        xfree(gbuf);
        xgethostbyname_free();    /* unlock mutex */

        return(SPF_TRUE);
      }
    } /* for */
 
    for (a = hp->h_aliases; *a; a++)
    {
      memcpy(&policy_addr.addr.s_addr, *a, SIZEOF(struct in_addr));

      xvprintf("IN CNAME; Checking: %lu\n", policy_addr.addr.s_addr);

      /* cidr is assumed checked by the calling function! */
      policy_addr.cidr = cidr;

      if (UTIL_cidr_cmp(&policy_addr, &p->addr) == SPF_TRUE)
      {
        *a = NULL;

        UTIL_assoc_prefix(p, SPF_PASS, NULL);

        xfree(copy);
        xfree(gbuf);
        xgethostbyname_free();    /* unlock mutex */

        return(SPF_TRUE);
      }
    } /* for */
  } /* if .. xgethostbyname */
  else
  {
    xvprintf("No address associated with hostname [%s]; Reason: %s\n",
      s, hstrerror(tmp_errno));
  }

  xfree(copy);
  xfree(gbuf);
  xgethostbyname_free();

  return(SPF_FALSE);
}


/* UTIL_ptr_cmp
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/08/04
*
*  Desc:
*          gethostbyaddr is broken in linux.  ?->h_aliases is not NULL,
*  however, it doesn't contain any valid pointers either.  It grabs the
*  first (and of course this is random) hostname it gets and thats all.
*  As tested in FreeBSD however this call works.  At any rate, I've
*  written a function to deal with this called DNS_ptr_answer.  From here
*  that function is called which handles the reverse lookups and then
*  attempts to "validate" each returned hostname by in turn looking it up
*  to confirm if the ip address SPF_MATCHes.  Returns SPF_TRUE on succes, and SPF_FALSE
*  on failure.
*
*  When passed SPF_TRUE copies into p->ptr_mhost, when SPF_FALSE copies
*  into p->r_vhname
*
*  Note:
*          We need to define and set a limit on the number of recursive
*  lookups.  I recall seeing this in the RFC, we should discuss this.
*
*/
SPF_BOOL UTIL_ptr_cmp(peer_info_t *p, const char *s)
{
  char *ptr_addr = NULL;    /* reversed address into PTR format */
  char *tmp_ptr  = NULL;    /* utility pointer */


  if (s == NULL)
  {
    xepprintf("Passed string is NULL.  Abort!\n");

    return(SPF_FALSE);
  }

  xvprintf("called with [%s]\n", s);

  /* reverse of rpeer */
  ptr_addr = UTIL_rev_addr(p->r_ip);

  xvprintf("address: %s\n", ptr_addr);

  if ((s = strstr(s, ":")) != NULL)
  {
    s++;
    tmp_ptr = xstrndup(s, (strlen(s) + 1));
  }
  else
  {
    tmp_ptr = xstrndup(p->current_domain, SPF_MAX_HNAME);
  }

  if (DNS_query(p, ptr_addr, T_PTR, tmp_ptr) != (char *)SPF_TRUE)
  {
    xvprintf("Failed to pass SPF PTR mechanism check:%s\n", "");
    xvprintf("the domain pointed to by %s is not a valid subdomain of %s\n",
      ptr_addr, tmp_ptr);

    xfree(ptr_addr);
    xfree(tmp_ptr);

    return(SPF_FALSE);
  }

  xvprintf("PTR lookup succeeded: [%s]:[%s]\n", p->rs,
    p->error);

  xfree(ptr_addr);
  xfree(tmp_ptr);

  return(SPF_TRUE);
}


/* UTIL_get_policy_mech
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/19/03
*
*  Desc:
*          Examins 's' and attempts to determine which SPF_MECHANISM
*  enumeration the matches a portion of the contents of the string.
*
*  Because this library only (currently) supports SPFv1 the check 
*  for an SPFv1 version is very stringent.
*
*/
SPF_MECHANISM UTIL_get_policy_mech(const char *s)
{
  if (s == NULL || !s)
  {
    xepprintf("passed a NULL string. Abort!\n");

    return(NO_POLICY);
  }

  xvprintf("called with: [%s]\n", s);

  if (strncmp(s, "v=spf1", 6) == 0)
  {
    xvprintf("leaving func; returning %i (VERSION)\n", VERSION);

    return(VERSION);
  }
  else if (strncmp(s, "ip4:", 4) == 0 )
  {
    xvprintf("leaving func; returning %i (IP4)\n", IP4);

    return(IP4);
  }
  else if (strncmp(s, "ip6:", 4) == 0)
  {
    xvprintf("leaving func; returning %i (IP6)\n", IP6);

    return(IP6);
  }
  else if (strncmp(s, "all", 3) == 0)
  {
    xvprintf("leaving func; returning %i (ALL)\n", ALL);

    return(ALL);
  }
  else if (strncmp(s, "mx", 2) == 0)
  {
    xvprintf("leaving func; returning %i (MX)\n", MX);

    return(MX);
  }
  else if (strncmp(s, "a:", 2) == 0 || (*s == 'a' && *(s + 1) == '/')
    ||  ((*s == 'a') && !*(s + 1)))
  {
    xvprintf("leaving func; returning %i (A)\n", A);

    return(A);
  }
  else if (strncmp(s, "ptr", 3) == 0)
  {
    xvprintf("leaving func; returning %i (PTR)\n", PTR);

    return(PTR);
  }
  else if (strncmp(s, "include:", 7) == 0)
  {
    xvprintf("leaving func; returning %i (INCLUDE)\n", INCLUDE);

    return(INCLUDE);
  }
  else if (strncmp(s, "exists:", 6) == 0)
  {
    xvprintf("leaving func; returning %i (EXISTS)\n", EXISTS);

    return(EXISTS);
  }
  else if (strncmp(s, "redirect=", 9) == 0)
  {
    xvprintf("leaving func; returning %i (REDIRECT)\n", REDIRECT);

    return(REDIRECT);
  }
  else if (strncmp(s, "exp=", 3) == 0)
  {
    xvprintf("leaving func; returning %i (EXPLAIN)\n", EXPLAIN);

    return(EXPLAIN);
  }
  else if (strncmp(s, "default", 7) == 0)
  {
    xvprintf("leaving func; returning %i (DEFAULT)\n", DEFAULT);

    return(DEFAULT);
  }
  else if (strstr(s, ":"))
  {
    xvprintf("leaving func; returning %i (UNMECH)\n", UNMECH);

    return(UNMECH);
  }

  xpprintf("leaving func; returning NO_POLICY\n");
  return(NO_POLICY);
}


/* UTIL_assoc_prefix
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/28/04
*
*  Desc:
*          Examins s and attempts to determine which SPF_MECHANISM_PREFIX
*  enumeration the string SPF_MATCHes based on the its contents (which is a
*  single char.  Upon a SPF_PASS it stores the appropriate value inside of
*  the passed peer_info structure.  SPF_TRUE upon success, SPF_FALSE upon failure.
*  Also upon failure SPF_ERROR (SPF_RESULT_TYPE) is stored in peer_info.
*
*
*/
SPF_BOOL UTIL_assoc_prefix(peer_info_t *p, SPF_RESULT res, const char *s)
{
  int16_t pos = 0;      /* position in s string */


   /* 
   * for whatever result happens to match the case, a debug string is 
   * printed (if compiled with), the level of recursion is made known through
   * this. An appropriate SPF_RESULT is assigned to the passed peer_info_t 
   * structure's 'p->RES' variable.  In addition a short SPF_RESULT string
   * (here is an example use of the spf_result_t structure spoke of in SPF_init)
   * is stored in 'p->rs', and finally an error string is stored in 
   * 'p->error'.  This string encompasses all SPF query return types though,
   * it is not only populated upon a parse error, so don't hesitate to reference
   * it when looking for a verbose explanation as to the result of an SPF parse.
  */

  if (s != NULL)
  {
    xvprintf("Entering function (%i) [%s]\n", res, s);

    /* support for old school deprecated mechanism "default" */
    if (strncmp(s, "default", 7) == 0 && (pos = UTIL_index(s, '=')) > 0)
    {
      s += (pos + 1); /* move past default= */
      if (strncmp(s, "deny", 4) == 0)
      {
        xvprintf("Stored SPF_H_FAIL (%i) (%i)\n",
          res, SPF_H_FAIL);

        p->RES = SPF_H_FAIL;
        p->rs  = p->spf_result[SPF_H_FAIL].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_TRUE);
      }
      else if (strncmp(s, "pass", 4) == 0)
      {
        xvprintf("Stored SPF_PASS (%i) (%i)\n",
          res, SPF_PASS);

        p->RES = SPF_PASS;
        p->rs  = p->spf_result[SPF_PASS].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_TRUE);
      }
      else if (strncmp(s, "softdeny", 8) == 0)
      {
        xvprintf("Stored SPF_S_FAIL (%i) (%i)\n",
          res, SPF_S_FAIL);

        p->RES = SPF_S_FAIL;
        p->rs  = p->spf_result[SPF_S_FAIL].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_TRUE);
      }
      else if (strncmp(s, "unknown", 7) == 0)
      {
        xvprintf("Stored SPF_NEUTRAL (%i) (%i)\n",
          res, SPF_NEUTRAL);

        p->RES = SPF_NEUTRAL;
        p->rs  = p->spf_result[SPF_NEUTRAL].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_TRUE);
      }
      else if (strncmp(s, "include", 7) == 0)
      {
        xvprintf("Stored SPF_UNKNOWN (%i) (%i)\n", res, SPF_UNKNOWN);

        p->RES = SPF_UNKNOWN;
        p->rs  = p->spf_result[SPF_UNKNOWN].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_TRUE);
      }
      else
      {
        xvprintf("Stored SPF_ERROR (%i) (%i)\n", res, SPF_ERROR);

        p->RES = SPF_UNKNOWN;
        p->rs  = p->spf_result[SPF_UNKNOWN].s;

        snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
          p->rs, p->last_m);

        return(SPF_FALSE);
      }
    }
  }

  switch (res)
  {
    /* */
    case SPF_PASS:
    {
      xvprintf("Stored SPF_PASS (%i) (%i)\n", res, SPF_PASS);

      p->RES = SPF_PASS;
      p->rs  = p->spf_result[SPF_PASS].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_PASS */

    /* */
    case SPF_NONE:
    {
      xvprintf("Stored SPF_NONE (%i) (%i)\n", res, SPF_NONE);

      p->RES = SPF_NONE;
      p->rs  = p->spf_result[SPF_NONE].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_NONE */

    /* */
    case SPF_S_FAIL:
    {
      xvprintf("Stored SPF_S_FAIL (%i) (%i)\n", res, SPF_S_FAIL);

      p->RES = SPF_S_FAIL;
      p->rs  = p->spf_result[SPF_S_FAIL].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_S_FAIL */

    /* */
    case SPF_H_FAIL:
    {
      xvprintf("Stored SPF_H_FAIL (%i) (%i)\n",
        res, SPF_H_FAIL);

      p->RES = SPF_H_FAIL;
      p->rs  = p->spf_result[SPF_H_FAIL].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_H_FAIL */

    /* */
    case SPF_NEUTRAL:
    {
      xvprintf("Stored SPF_NEUTRAL (%i) (%i)\n",
        res, SPF_NEUTRAL);

      p->RES = SPF_NEUTRAL;
      p->rs  = p->spf_result[SPF_NEUTRAL].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_NEUTRAL */

    /* */
    case SPF_UNKNOWN:
    {
      xvprintf("Stored SPF_UNKNOWN (%i) (%i)\n",
        res, SPF_UNKNOWN);

      p->RES = SPF_UNKNOWN;
      p->rs  = p->spf_result[SPF_UNKNOWN].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_UNKNOWN */

    /* */
    case SPF_ERROR:
    {
      xvprintf("Stored SPF_ERROR (%i) (%i)\n",
        p, SPF_ERROR);

      p->RES = SPF_ERROR;
      p->rs  = p->spf_result[SPF_ERROR].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_ERROR */

    /* */
    case SPF_UNMECH:
    {
      xvprintf("Stored SPF_UNMECH (%i) (%i)\n",
        res, SPF_UNMECH);

      p->RES = SPF_UNMECH;
      p->rs  = p->spf_result[SPF_UNMECH].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* SPF_UNMECH */

    /* */
    default:
    {
      xvprintf("Stored SPF_PASS (%i) (%i)\n",
        res, SPF_PASS);

      p->RES = SPF_PASS;
      p->rs  = p->spf_result[SPF_PASS].s;

      snprintf(p->error, SPF_MAX_ERROR, "policy result: [%s] from rule [%s]",
        p->rs, p->last_m);

      return(SPF_TRUE);
    } /* default */

  } /* switch */

  xepprintf("leaving func; returning SPF_FALSE.\n");

  return(SPF_FALSE);
}


/* UTIL_get_mech_prefix
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/31/03
*
*  Desc:
*          Examins s and attempts to determine which SPF_RESULT_P
*  enumeration the string SPF_MATCHes based on the its contents (which is a
*  single char.  Returns SPF_PASS if a valid prefix is not specified.
*  Valid prefixes are: + (permit), - (deny), ~ (softfail) and ? (SPF_NEUTRAL).
*
*/
SPF_RESULT UTIL_get_mech_prefix(peer_info_t *p, const char *s)
{
  int16_t pos = 0;    /* position in s */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(SPF_ERROR);
  }

  xprintf("called with char: [%s]\n", s);
  snprintf(p->last_m, SPF_MAX_HNAME, "%s", s);

  switch (*s)
  {
    /* */
    case '+':
    {
      p->RES_P = SPF_PASS;
      xvprintf("leaving func; returning SPF_PASS [%s] %i\n", s, SPF_PASS);

      return(SPF_PASS);
    } /* '+' */

    /* */
    case '-':
    {
      p->RES_P = SPF_H_FAIL;
      xvprintf("leaving func; returning SPF_H_FAIL [%s] %i\n", s, SPF_H_FAIL);

       return(SPF_H_FAIL);
    } /* '-' */

    /* */
    case '?':
    {
      p->RES_P = SPF_NEUTRAL;
      xvprintf("leaving func; returning SPF_NEUTRAL [%s] %i\n",
        s, SPF_NEUTRAL);

      return(SPF_NEUTRAL);
    } /* '?' */

    /* */
    case '~':
    {
      p->RES_P = SPF_S_FAIL;
      xvprintf("leaving func; returning SPF_S_FAIL [%s] %i\n", s, SPF_S_FAIL);

      return(SPF_S_FAIL);
    } /* '~' */

    /* */
    default:
    {
      if (p->ALL == SPF_TRUE)
      {
        p->RES_P = SPF_NEUTRAL;
        xvprintf("leaving func; returning (def) SPF_NEUTRAL [%s] %i\n",
          s, SPF_NEUTRAL);
      }
      else
      {
        p->RES_P = SPF_PASS;
        xvprintf("leaving func; returning (def) SPF_PASS [%s] %i\n",
          s, SPF_PASS);
      }

      xvprintf("leaving func; returning (%i)\n", p->RES_P);

      return(p->RES_P);
   } /* default */

  } /* switch */

   /*
   * The code in the following statement is for the
   * deprecated mechanism "default" and is only here to attempt
   * to support exceptionally tardy early adopters whom likely
   * at this time no longer exist.  As such this code is not
   * present in the current development versions of this library
  */
  if ((pos = UTIL_index(s, '=')) > 0)
  {
    s += (pos + 1); /* move past default= */

    if (strncmp(s, "deny", 4) == 0)
    {
      p->RES_P = SPF_H_FAIL;
      xvprintf("leaving func; returning SPF_H_FAIL on [%s]\n", s);

      return(SPF_H_FAIL);
    }
    else if (strncmp(s, "pass", 4) == 0)
    {
      p->RES_P = SPF_PASS;
      xvprintf("leaving func; returning SPF_PASS on [%s]\n", s);

      return(SPF_PASS);
    }
    else if (strncmp(s, "softdeny", 8) == 0)
    {
      p->RES_P = SPF_S_FAIL;
      xvprintf("leaving func; returning SPF_S_FAIL on [%s]\n", s);

      return(SPF_S_FAIL);
    }
    else if (strncmp(s, "unknown", 7) == 0)
    {
      p->RES_P = SPF_NEUTRAL;
      xvprintf("leaving func; returning SPF_NEUTRAL on [%s]\n", s);

      return(SPF_NEUTRAL);
    }
    else
    {
      xvprintf("leaving func; returning SPF_NEUTRAL on [%s]\n", s);

      return(SPF_NEUTRAL);
    }
  }

  xvprintf("leaving func; returning SPF_ERROR on [%s]\n", s);

  return(SPF_ERROR);
}


/* UTIL_expand_ip
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/26/03
*
*  Desc:
*          Expands an ip4 policy mechanism string into a policy_addr_t
*  structure which it allocates memory for and then returns.  The RFC
*  specifies that if a cidr block is not specified then /32 isused.
*
*  Both 'ip' and 'policy_addr' are dynamically allocated, and must be
*  explicitly freed before any negative activity resulting in a NULL
*  return response.
*
*  On success returns a pointer to a policy_addr_t structure, on
*  SPF_ERROR returns NULL.
*
*/
policy_addr_t *UTIL_expand_ip(const char *s)
{
  int8_t cidr = 0;                       /* temporary storage for netmask */

  size_t len = 0;                        /* length of string passed */
  size_t pos = 0;                        /* position of break points in string */

  char *ip = NULL;                       /* temporary storage for ip address */

  const char *token_ptr = NULL;          /* our position in the token */

  policy_addr_t *policy_addr = NULL;     /* ip/mask return structure */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(NULL);
  }

  len = strlen(s);
  token_ptr = s;

  xvprintf("called with string: [%s]\n", token_ptr);

  if ((pos = UTIL_index(token_ptr, ':')) == 0)
  {
    xvprintf("SPF_ERROR: Unable to get position on token [%s]\n",
      token_ptr);

    return(NULL);
  }

  /* jump past the ip4: portion */
  token_ptr += (pos + 1);

  policy_addr = xmalloc(SIZEOF(policy_addr_t));

  /* jump past the ip4: portion (to get length of ip) */
  if ((pos = UTIL_index(token_ptr, '/')) == 0)
  {
    xvprintf("Unable to get position on token [%s], assuming /32 cidr " \
      "block\n", token_ptr);

    pos = strlen(token_ptr);
    cidr = 32;
  }

  /* allocate space and dump the ip address there */
  ip = xstrndup(token_ptr, (pos + 1));

  /* copy it over to the policy_addr structure */
  if ((inet_pton(AF_INET, ip, &policy_addr->addr)) == 0)
  {
    xvprintf("SPF_ERROR: inet_pton unable to convert ip to binary " \
      "[%s]\n", ip);

    xfree(policy_addr);
    xfree(ip);
    
    return(NULL);
  }

  if (cidr != 32)
  {
    token_ptr += (pos + 1);    /* skip over the forward slash */
    cidr = atoi(token_ptr);    /* convert the string to an integer */
  }

  if ((cidr < 0) || (cidr > 32))
  {
    xvprintf("ERROR: cidr violation (%u)\n", cidr);

    xfree(ip);
    xfree(policy_addr);

    return(NULL);
  }

  policy_addr->cidr = cidr;    /* copy it over to the policy_addr structure */

  xvprintf("CIDR: (%i) IP: [%s]\n",
    policy_addr->cidr, inet_ntoa(policy_addr->addr));

  xfree(ip);

  return(policy_addr);
}


/*  UTIL_is_sid
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/07/04
*
*  Desc:
*          Passed the entire T_TXT record from a DNS query and performs
*  a check to see if the record is a valid SenderID record.
*
*  Return: 
*          SPF_TRUE - T_TXT record contained a valid SenderID record
*          SPF_FALSE - T_TXT record did not contain a valid SenderID record
*
*/
SPF_BOOL UTIL_is_sid(const char *s)
{
  char *tmp = NULL;


  if (s && (s != NULL))
  {
    xvprintf("called with: [%s]\n", s);

    if ((tmp = strstr(s, "v=spf2.0/pra")) != NULL)
    {
      xvprintf("discovered a SenderID record [%s]\n", tmp);

      return(SPF_TRUE);
    }
  }

  return(SPF_FALSE);
}

 
/*  UTIL_is_ip
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/18/04
*
*  Desc:
*         Is the passed string (limited to between 0 - 255 by type)
*  contains a valid ip address or not.  I'm not sure if this is useful
*  anymore but at one point I was using it to tell if the passed macro
*  contained an ip address or not when passed as a string.
*
*/
SPF_BOOL UTIL_is_ip(const char *id)
{
  u_int8_t i = 0;    /* utility */

  if (!id)
  {
    xepprintf("called without an IP address!\n");
  
    return(SPF_FALSE);
  }

  xvprintf("called with address: [%s]\n", id);

  while (*id)
  {
    if (*id == '.')
    {
      i++;
    }
    else if (isdigit(*id) == 0)
    {
      return(SPF_FALSE);
    }
    id++;
  }

  if (i == 3)
  {
    return(SPF_TRUE);
  }

  xpprintf("leaving func; returning SPF_FALSE\n");

  return(SPF_FALSE);
}


/* UTIL_rev_addr
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/04/04
*
*  Desc:
*          Using a passed ip address it will reverse it and slap
*  .in-addr.arpa on the end of it making it ready for a proper PTR query
*
*  Notes:  Write additional code to handle IP6 addresses
*
*/
char *UTIL_rev_addr(const char *s)
{
  u_int8_t i = 0;           /* utility */
  u_int8_t tmp[4][1];       /* temporary storage for ip integers */

  size_t len = 0;           /* length of to be allocated string */

  char *cp       = NULL;    /* copy of passed string */
  char *token    = NULL;    /* token for splitting apart ip address */
  char *new_addr = NULL;    /* allocate string for reversed address */


  if (s == NULL)
  {
    xepprintf("passed a null string.  Abort!\n");

    return(NULL);
  }

  len = (strlen(s) + 1);

  xprintf("called with: [%s] len: (%i)\n", s, (len - 1));

  cp    = xstrndup(s, len);
  token = strtok(cp, ".");

  while ((token != NULL) && (i <= 3))
  {
    xvprintf("token : [%s]\n", token);

    tmp[i][0] = atoi(token);
    token     = strtok(NULL, ".");
    i++;
  }

  xfree(cp);

  /* + .in-addr.arpa\0 */
  new_addr = xmalloc(len + 13);

  snprintf(new_addr, (len + 13), "%u.%u.%u.%u.in-addr.arpa",
    tmp[3][0], tmp[2][0], tmp[1][0], tmp[0][0]);

  xvprintf("leaving func; returning reversed ip: %s\n", new_addr);

  return(new_addr);
}


/* UTIL_get_dname
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/27/04
*
*  Desc:
*          s contains a hostname which is then looked through and split
*  apart, always leaving one '.' delimiter left so you are left with
*  domain.tld.  domain.tld is then put into newly allocated memory and
*  returned to the calling function.  Upon failure, returns NULL.
*  Calling function is required to free the memory.
*
*/
char *UTIL_get_dname(const char *s)
{
  u_int8_t i = 0;      /* how many delimiters in s */

  char *buf = NULL;    /* return string to be allocated */


  if (s == NULL)
  {
    xepprintf("called with NULL.  Abort!\n");

    return(NULL);
  }

  xvprintf("called with [%s]\n", s);

  i = UTIL_count_delim(s, '.');

  switch (i)
  {
    case 0:
    {
      break;
    }

    case 1:
    {
      buf = xstrndup(s, (strlen(s) + 1));
      xprintf("leaving func; returning buffer: [%s]\n", buf);

      return(buf);
    }

    default:
    {
      buf = UTIL_split_str(s, '.', (i - 1));
      xprintf("leaving func; returning buffer: [%s]\n", buf);

      return(buf);
    }

  } /* switch */

  xepprintf("leaving func; returning NULL\n");

  return(NULL);
}


/* UTIL_cidr_cmp
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/26/03
*
*  Desc:
*          Compares an IP address (connected peer) against another IP
*  address (found in a policy lookup) using a netmask (also found from
*  a policy lookup) to see if the peer address is legal within that
*  netmask.  Returns SPF_TRUE if its valid, SPF_FALSE if not.
*
*  Notes:  Write additional comparisons to handle IP6 addresses
*
*/
SPF_BOOL UTIL_cidr_cmp(const policy_addr_t *policy_addr, const struct in_addr
  *peer_addr)
{
  u_int32_t a = 0;           /* working buf */
  u_int32_t b = 0;           /* working buf */

  char *peer_ip   = NULL;    /* ip address of connected peer */
  char *policy_ip = NULL;    /* ip address of current SPF policy */


  if ((policy_addr->addr.s_addr <= 0) && (peer_addr->s_addr <= 0))
  {
    xepprintf("Passed with NULL chars.  Aborting.\n");

    return(SPF_FALSE);
  }

  xvprintf("POL: %lu PEER: %lu CIDR: %i\n", policy_addr->addr.s_addr,
    peer_addr->s_addr, policy_addr->cidr);

   /*
   * Packets come in off the wire in whats called "network byte order"
   * which does't work very well when trying to compute if one address
   * is masked by another using a CIDR calculation so the 'ntohl' is 
   * issued on them to change their byte order
  */
  a = ntohl(peer_addr->s_addr);
  b = ntohl(policy_addr->addr.s_addr);

  if (policy_addr->cidr != 32)
  {
    if ((a&(~0U<<(32-policy_addr->cidr))) != (b&(~0U<<(32-policy_addr->cidr))))
    {
      return(SPF_FALSE);
    }
  }
  else
  {
    if (peer_addr->s_addr != policy_addr->addr.s_addr)
    {
      xvprintf("%lu and %lu using 32 cidr do not match\n",
        peer_addr->s_addr, policy_addr->addr.s_addr);

      return(SPF_FALSE);
    }
  }

  /* these are done here just for debugger remove later */
  peer_ip   = xstrndup(inet_ntoa(*peer_addr), SPF_MAX_IP_ADDR);
  policy_ip = xstrndup(inet_ntoa(policy_addr->addr), SPF_MAX_IP_ADDR);

  xvprintf("Peer: [%s] matches address %s with network %i\n",
    peer_ip, policy_ip, policy_addr->cidr);

  xfree(peer_ip);
  xfree(policy_ip);

  return(SPF_TRUE);
}


/* UTIL_validate_ptr
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/26/03
*
*  Desc:
*          Using the ip address found in the passed peer_info structure,
*  a PTR lookup is made and if a record exists then this is record is compared
*  against the hostname the client wishes to send mail from.  If the tld matches
*  the tld found during this query, this would be a 'valdiated' PTR.  If a match
*  can not be found we return SPF_FALSE.  If a match is made we return SPF_TRUE.
*
*  Notes:  Write additional comparisons to handle IP6 addresses
*
*/
SPF_BOOL UTIL_validate_ptr(peer_info_t *p)
{
  char *ptr_addr = NULL;    /* reversed address into PTR format */
  char *tmp_ptr  = NULL;    /* utility pointer */


  if (!p)
  {
    xepprintf("called with an invalid peer info structure!\n");

    return(SPF_FALSE);
  }

  /* reverse of the address in peer_info */
  ptr_addr = UTIL_rev_addr(p->r_ip);
  xvprintf("[address: %s]\n", ptr_addr);

  tmp_ptr = xstrndup(p->current_domain, SPF_MAX_HNAME);

  if (DNS_query(p, ptr_addr, T_PTR, tmp_ptr) != (char *)SPF_TRUE)
  {
    xvprintf("PTR lookup failed: [%s] [%s]\n", p->rs, p->error);

    xfree(ptr_addr);
    xfree(tmp_ptr);

    return(SPF_FALSE);
  }

  xvprintf("Peer [%s] successfully validated hostname [%s]\n",
    p->r_ip, p->r_vhname);

  xfree(ptr_addr);
  xfree(tmp_ptr);

  return(SPF_TRUE);
}


/* UTIL_validate_hostname
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/08/04
*
*  Desc:
*          s contains a hostname which is then looked up to find any
*  of the returned ip addresses SPF_PASS the remote peers.  On a successful
*  SPF_PASS returns SPF_TRUE.  When no SPF_PASS is made, returns SPF_FALSE.
*
*  Note:
*          We need to define and set a limit on the number of recursive
*  lookups.  I recall seeing this in the RFC, we should discuss this.
*
*  Date:  08/28/04 by James
*
*  Desc:
*          Added buffer for reentrant gethostbyname wrapper and changed
*  gethostbyname calls to use the MACRO wrapper xgethostbyname()
*
*/
SPF_BOOL UTIL_validate_hostname(peer_info_t *p, const char *s, const int8_t cidr)
{
  int tmp_errno = 0;                  /* temporary errno placeholder */

  char **a   = NULL;                  /* work ptr for list recursion */

  char *ip   = NULL;                  /* ip address */
  char *gbuf = NULL;                  /* reentrant buffer for gethostbyname_r */

  struct in_addr *addr = NULL;        /* connected peer's address */
  
  struct hostent *hp    = NULL;       /* hostent structure */
  struct hostent tmp_hp = {0};        /* temporary hostent structure */
  
  policy_addr_t policy_addr = {0};    /* used for cidr calculations */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.\n");

    return(SPF_FALSE);
  }

  xvprintf("called with: (%lu) and [%s]\n", p->r_ip, s);

  gbuf = xmalloc(SPF_MAX_GHBNR_DBUF);
  memset(&tmp_hp, '\0', SIZEOF(struct hostent));

  if ((hp = xgethostbyname(s, &tmp_hp, gbuf, SPF_MAX_GHBNR_DBUF,
    &tmp_errno)) != NULL)
  {
    /* for each hostname in the list, perform CIDR checks */
    for (a = hp->h_addr_list; *a; a++)
    {
      addr = xmalloc(SIZEOF(struct in_addr));
      memcpy(&addr->s_addr, *a, SIZEOF(struct in_addr));
      ip = xstrndup(inet_ntoa(*addr), SPF_MAX_IP_ADDR);

      xvprintf("CLI: %s (%lu) SRV: %s (%lu)\n", ip, addr->s_addr,
        p->r_ip, p->addr.s_addr);

      if (cidr == 32)
      {
        if (((struct in_addr *)(*a))->s_addr == p->addr.s_addr)
        {
          xvprintf("%s (%lu) matches %s (%lu)\n", ip,
            ((struct in_addr *)(*a))->s_addr, p->r_ip, p->addr.s_addr);

          UTIL_assoc_prefix(p, SPF_PASS, NULL);

          xfree(ip);
          xfree(gbuf);
          xfree(addr);
          xgethostbyname_free();    /* unlock mutex */

          xpprintf("leaving func; returnining SPF_TRUE\n");

          return(SPF_TRUE);
        }
      }
      else if ((cidr < 32) && (cidr >= 8))
      {
        /* convert from character string to dotted quad notation */
        if ((inet_pton(AF_INET, ip, &policy_addr.addr)) == 0)
        {
          xepprintf("Unable to execute inet_pton()\n");
        }

        policy_addr.cidr = cidr;

        xvprintf("Address: %lu with CIDR %i\n",
          policy_addr.addr.s_addr, policy_addr.cidr);

        /* perform CIDR comparison of 'policy_addr' vs 'p->addr' */ 
        if ((UTIL_cidr_cmp(&policy_addr, &p->addr)) == SPF_TRUE)
        {
          xvprintf("(%lu) matches (%lu) with CIDR %u\n",
            policy_addr.addr.s_addr, p->addr.s_addr, cidr);

          /* associate an SPF prefix (-,+,~,?) with this check */
          UTIL_assoc_prefix(p, SPF_PASS, NULL);

          xfree(ip);
          xfree(gbuf);
          xfree(addr);
          xgethostbyname_free();

          xpprintf("leaving func; returnining SPF_TRUE\n");

          return(SPF_TRUE);
        }
      } /* else if */

      xfree(ip);
      xfree(addr);

    } /* for */

    /* for each alias (CNAME) perform a CIDR check */
    for (a = hp->h_aliases; *a; a++)
    {
      addr = xmalloc(SIZEOF(struct in_addr));
      memcpy(&addr->s_addr, *a, SIZEOF(struct in_addr));
      ip = xstrndup(inet_ntoa(*addr), SPF_MAX_IP_ADDR);

      xvprintf("client: %s (%lu); policy: %s (%lu)\n",
        ip, addr->s_addr, p->r_ip, p->addr.s_addr);

      if (cidr == 32)
      {
        if (((struct in_addr *)(*a))->s_addr == p->addr.s_addr)
        {
          xvprintf("IN A: client: %s (%lu) matches policy: %s (%lu)\n",
            ip, ((struct in_addr *)(*a))->s_addr, p->r_ip, p->addr.s_addr);

          xfree(ip);
          xfree(gbuf);
          xfree(addr);
          xgethostbyname_free();

          xpprintf("leaving func; returnining SPF_TRUE\n");

          return(SPF_TRUE);
        }
      }
      else if ((cidr < 32) && (cidr >= 8))
      {
        if (inet_pton(AF_INET, ip, &policy_addr.addr) == 0)
        {
          xepprintf("Unable to execute inet_pton()\n");
        }

        policy_addr.cidr = cidr;

        if (UTIL_cidr_cmp(&policy_addr, &p->addr) == SPF_TRUE)
        {
          xvprintf("client: (%lu) matches policy (%lu) with CIDR %u\n",
            policy_addr.addr.s_addr, p->addr.s_addr, cidr);

          /* associate an SPF prefix (-,+,~,?) with this check */
          UTIL_assoc_prefix(p, SPF_PASS, NULL);

          xfree(ip);
          xfree(gbuf);
          xfree(addr);
          xgethostbyname_free();

          xpprintf("leaving func; returnining SPF_TRUE\n");

          return(SPF_TRUE);
        }
      } /* else */
      
      xfree(ip);
      xfree(addr);
 
    } /* for */
  } /* if .. xgethostbyname() */
  else
  {
    xvprintf("No address associated with hostname [%s]; Reason: %s\n",
      s, hstrerror(tmp_errno));
  }

  xfree(gbuf);
  xgethostbyname_free();

  xpprintf("leaving func; returning SPF_FALSE\n");

  return(SPF_FALSE);
}


/* UTIL_url_encode
*
*  Author: Sean Comeau <scomeau@obscurity.org>
*
*  Date:   01/06/04
*
*  Desc:
*          "URL-Encode" characters that are "unsafe" or "prohibited" from a URL.
*  Upon success returns a pointer to a newly allocated memory containing the
*  encoded string.  Upon failure returns a NULL pointer.  Failure
*  indicates either a failure to allocate new memory, or the passed string
*  did not contain any questionable characters and hence did not require
*  encoding.
*
*/
char *UTIL_url_encode(const char *s)
{
  int len = 0;             /* length of passed string * 3*/

  char *new     = NULL;    /* newly allocated memory */
  char *encoded = NULL;    /* encoded return string */


  if (s != NULL)
  {
     /*
     * length of the string times 3 is the maximum possible size a
     * URL encoded string should ever be able to expand to.
    */
    len = (strlen(s) * 3);
  }
  else
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(NULL);
  }

  encoded = new = xmalloc(len);

  while (*s != '\0')
  {
    if (urlchr_test(*s) == 0)
    {
      *new++ = *s++;
    }
    else
    {
      /* this obviously NULL terminates, do we want this? */
      snprintf(new, 4, "%%%x", *s);
      new += 3;
      s++;
    }
  }

  *new++ = '\0';
  xvprintf("leaving func; returning [%s]\n", encoded);

  return(encoded);
}


/* UTIL_reverse
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/06/04
*
*  Desc:
*          Takes a string and rebuilds it in reverse order using the
*  supplied delimiter.  The string will always be rebuilt using a
*  '.' char as per the RFC.
*
*/
char *UTIL_reverse(const char *s, const char delim)
{
  size_t len = 0;                        /* length of s */

  char *buf = NULL;                      /* return buffer */
  char *p   = NULL;                      /* working pointer */
  char *cp  = NULL;                      /* working pointer */
  char *c   = NULL;                      /* working pointer */

  split_str_t *master = NULL;            /* list pointers */

  split_str_node_t *c_node    = NULL;    /* c_node node */
  split_str_node_t *kill_node = NULL;    /* temp node used in destruction */


  if (s == NULL)
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(NULL);
  }

  xvprintf("called with [%s] and delim (%c)\n", s, delim);

  len = strlen(s);
  cp  = c = xstrndup(s, (len + 1));

  master           = xmalloc(SIZEOF(split_str_t));
  master->head     = NULL;
  master->tail     = NULL;
  master->elements = 0;

  /* 
   *  Comment: James Couzens <jcouzens@codeshare.ca>
   *
   *  Date: 01/22/04
   *
   * we do not want the trailing delim so the first iteration of this
   * loop we call UTIL_addnode with 0, which tells it not to allocate
   * the extra byte for the trailing delimiter.  This is done only
   * when passed an IP address, and this is because when reversing we
   * want: 1.0.168.192. and not .1.0.168.192
   *
  */
  
  len++;
  buf = xmalloc(len);
  while ((p = strrchr(cp, delim)) != NULL)
  {
    p++;   /* remove period */
    UTIL_addnode(master, p, SPF_TRUE);
    p--;   /* bring it back */
    *p = '\0';
  }

  UTIL_addnode(master, cp, SPF_FALSE);

  c_node = master->head;
  while ((kill_node = c_node) != NULL)
  {
    strncat(buf, kill_node->s, kill_node->len);
    xfree(kill_node->s);
    c_node = c_node->next;
    xfree(kill_node);
  }

  xfree(cp);
  xfree(master);

  xvprintf("leaving func; returning [%s]\n", buf);

  return(buf);
}


/*  UTIL_addnode
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/18/04
*
*  Desc:
*         Allocates memory for a new node and slaps it on the end of
*  of the passed list.  In the process of doing so, when it comes to
*  the last element in the list, which is indicated by the SPF_BOOL
*  that is passed, a final '.' is either appended (SPF_TRUE) or not
*  (SPF_FALSE).  Function returns SPF_TRUE upon success, and SPF_FALSE upon
*  failure.
*
*/
SPF_BOOL UTIL_addnode(split_str_t *master, const char *s, SPF_BOOL last)
{
  size_t len = 0;                        /* length of s */

  split_str_node_t *c_node    = NULL;    /* c_node working node */
  split_str_node_t *new_node  = NULL;    /* newly allocated node */
  split_str_node_t *prev_node = NULL;    /* previous working node */


  if (!s || (s == NULL))
  {
    xepprintf("passed a NULL string.  Abort!\n");

    return(SPF_FALSE);
  }

  xvprintf("called with string: [%s]; boolean: [%s]\n",
    s, last ? "TRUE" : "FALSE");
 
  len = strlen(s);

  if (last == SPF_TRUE)
  {
    len += 2;
  }
  else
  {
    len++;
  }

  /* create new node */
  new_node = xmalloc(SIZEOF(split_str_node_t));

  /* set the new nodes next value NULL, and store s */
  new_node->next = NULL;

  new_node->s = xmalloc(len);

   /*
   *  Comment: James Couzens <jcouzens@codeshare.ca>
   *
   *  Date: 01/22/04
   *
   * section 7.1 (Macro definitions) of the RFC v02.9.5 indicates that we must
   * always rebuild the macro using the delimiter '.' and not the passed
   * delimiting character.
   *
  */
  snprintf(new_node->s, len, "%s%c", s, last ? '.' : '\0');
  new_node->len = (len - 1); /* don't count \0 */

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

  master->tail = new_node;
  master->elements++;

  xpprintf("leaving func; returning SPF_TRUE\n");

  return(SPF_TRUE);
}


/*  UTIL_delnode
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   10/06/04
*
*  Desc:
*         Iterate through the master list searching for a node whose string
*  buffer matches the contents of 's'.  When found that node is free'd and the
*  list continues until its end and then returns TRUE.  If it is not found,
*  we return SPF_FALSE.  
*
*/
SPF_BOOL UTIL_delnode(split_str_t *master, const char *s)
{
  SPF_BOOL DELETE_SUCCESS = SPF_FALSE;
  
  split_str_node_t *c_node    = NULL;
  split_str_node_t *kill_node = NULL;
  
  if (s == NULL)
  {
    xepprintf("called with empty comparison string, returning FALSE\n");
    
    return(SPF_FALSE);
  }
  
  c_node = master->head;

  while ((kill_node = c_node) != NULL)
  { 
    xvprintf("iterate include list: include:%s\n", kill_node->s);
    
    if (strcasecmp(kill_node->s, s) == 0)
    { 
      xvprintf("match found (%s == %s), removing node.\n",
        kill_node->s, s);
      
      /* remove the matched node's contents */  
      xfree(kill_node->s);
      kill_node->len = 0;
      
      /* iterate forward in the list to safely free the matched node */
      c_node = c_node->next;
      
      /* update the master list with a new head node and element count */
      master->head = c_node;
      master->elements--;
      
      /* free the structure of the matched node */
      xfree(kill_node);
      
      DELETE_SUCCESS = SPF_TRUE;
    }
    else
    {    
      c_node = c_node->next;
    }
    
    if (DELETE_SUCCESS == SPF_TRUE)
    {
      c_node    = NULL;
      kill_node = NULL;
    }
  }

  xvprintf("returning %s\n", DELETE_SUCCESS ? "SPF_TRUE" : "SPF_FALSE");
  
  return(DELETE_SUCCESS);
}


/* _UTIL_pthread_mutex
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   09/08/04
*
*  Desc:
*         Locks or unlocks the passed mutex based on the additional value
*  which is and enumerattion (SPF_BOOL)
*
*/
void _UTIL_pthread_mutex(void *mutex, SPF_BOOL action)
{

#ifdef _WITH_PTHREADS

  switch (action)
  {
    case SPF_TRUE:
    {
      pthread_mutex_lock((pthread_mutex_t *)mutex);

      return;
    }

    case SPF_FALSE:
    {    
      pthread_mutex_unlock((pthread_mutex_t *)mutex);

      return;
    }

  } /* switch */

#endif /* _WITH_PTHREADS */

  return;
}


/* end of util.c */
