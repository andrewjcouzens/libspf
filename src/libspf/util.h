/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  File:   util.h
*  Desc:   Utility function header file
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


#ifndef _UTIL_H
#define _UTIL_H 1

#include "../../config.h"         /* autoconf */
#include <stdio.h>                /* stdin / stdout */
#include <stdlib.h>               /* malloc / free */
#include <stdarg.h>               /* va_sprintf */
#include <string.h>               /* strstr / strdup */
#include <strings.h>              /* strcasecmp */
#include <unistd.h>               /* ? exit? */
#include <sys/socket.h>           /* inet_ functions / structs */
#include <netinet/in.h>           /* inet_ functions / structs */
#include <time.h>                 /* time_t */
#include <ctype.h>                /* isdigit .. */

/*
#ifdef _WITH_SOLARIS
#include <link.h>         */      /* uintptr_t */
/*#elif defined(__FreeBSD__)*/
/*#include <inttypes.h>       */  /* uintptr_t */
/*#else
#include <stdint.h>           */  /* uintptr_t */
/*#endif*/ /* _WITH_SOLARIS */

#ifdef _HAVE_INTTYPES_H
#include <inttypes.h>
#endif /* HAVE_INTTYPES_H */

#include "main.h"                 /* for the flags man */

#ifdef _WITH_PTHREADS
#include "dns.h"                  /* xgethostbyname */
#endif /* _WITH_PTHREADS */

#ifdef  HAVE__BEGIN_DECLS
__BEGIN_DECLS
#else
# ifdef __cplusplus
extern "C" {
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */



 /*
 *  define declarations
 *
*/

/* maximum size of buffer for date time stamp */
#define SPF_MAX_DATETIME 26

/* max size of gethostbyname_r data buffer */
#define SPF_MAX_GHBNR_DBUF 2048


 /*
 * In ANSI C, and indeed any rational implementation, size_t is also the
 * type returned by sizeof().  However, it seems there are some irrational
 * implementations out there, in which sizeof() returns an int even though
 * size_t is defined as long or unsigned long.  To ensure consistent results
 * we always use this SIZEOF() macro in place of using sizeof() directly.
*/
#define SIZEOF(object)  ((size_t) sizeof(object))


#ifndef HAVE___FUNCTION__
# ifdef HAVE___FUNC__
#  define __FUNCTION__  __func__
# else
#  define __FUNCTION__  "?"
# endif /* HAVE___FUNC__ */
#endif /* HAVE___FUNCTION__ */


 /*
 *  memory allocation and string handling wrapper macros
 *
*/

#define xmalloc(n)      UTIL_malloc(n, __FILE__, __LINE__, __FUNCTION__)
#define xrealloc(m, n)  UTIL_realloc(m, n, __FILE__, __LINE__, __FUNCTION__)
#define xfree(m)        UTIL_free(m, __FILE__, __LINE__, __FUNCTION__)
#define xstrdup(m)      UTIL_strdup(m)
#define xstrndup(m, n)  UTIL_strndup(m, n)


 /*
 *  printf wrapper macros
 *
*/

/* printf with variadic macros */
#define xprintf(format,...) \
  dbg_printf(FL_A, __FUNCTION__, __FILE__, __LINE__, format, __VA_ARGS__)

/* more verbose printf with variadic macros */
#define xvprintf(format,...) \
  dbg_printf(FL_B, __FUNCTION__, __FILE__, __LINE__, format, __VA_ARGS__)

/* printf without variadic macros (passing only a single string) */
#define xpprintf(s) \
  dbg_pprintf(FL_D, __FUNCTION__, __FILE__, __LINE__, s) 

/* error printf with variadic macros */
#define xeprintf(format,...) \
  dbg_printf(FL_E, __FUNCTION__, __FILE__, __LINE__, format, __VA_ARGS__)

/* error printf without variadic macros */
#define xepprintf(s)  \
  dbg_pprintf(FL_F, __FUNCTION__, __FILE__, __LINE__, s)


 /*
 *  threading wrapper macros
 *
*/

#define xpthread_mutex_lock(m)   _UTIL_pthread_mutex(m, SPF_TRUE)
#define xpthread_mutex_unlock(m) _UTIL_pthread_mutex(m, SPF_FALSE)


/* for handing debug modes */
#define f_bit_set(fl_bit_vector, bit) ((int)((fl_bit_vector)&(bit)))

/* this table and macro came from wget more or less */
#define urlchr_test(c) (urlchr_table[(unsigned char)(c)] & 1)
static const u_char urlchr_table[256] =
{
  1,  1,  1,  1,   1,  1,  1,  1,   /* NUL SOH STX ETX  EOT ENQ ACK BEL */
  1,  1,  1,  1,   1,  1,  1,  1,   /* BS  HT  LF  VT   FF  CR  SO  SI  */
  1,  1,  1,  1,   1,  1,  1,  1,   /* DLE DC1 DC2 DC3  DC4 NAK SYN ETB */
  1,  1,  1,  1,   1,  1,  1,  1,   /* CAN EM  SUB ESC  FS  GS  RS  US  */
  1,  0,  1,  1,   0,  1,  1,  0,   /* SP  !   "   #    $   %   &   '   */
  0,  0,  0,  1,   0,  0,  0,  1,   /* (   )   *   +    ,   -   .   /   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* 0   1   2   3    4   5   6   7   */
  0,  0,  1,  1,   1,  1,  1,  1,   /* 8   9   :   ;    <   =   >   ?   */
  1,  0,  0,  0,   0,  0,  0,  0,   /* @   A   B   C    D   E   F   G   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* H   I   J   K    L   M   N   O   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* P   Q   R   S    T   U   V   W   */
  0,  0,  0,  1,   1,  1,  1,  0,   /* X   Y   Z   [    \   ]   ^   _   */
  1,  0,  0,  0,   0,  0,  0,  0,   /* `   a   b   c    d   e   f   g   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* h   i   j   k    l   m   n   o   */
  0,  0,  0,  0,   0,  0,  0,  0,   /* p   q   r   s    t   u   v   w   */
  0,  0,  0,  1,   1,  1,  1,  1,   /* x   y   z   {    |   }   ~   DEL */

  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,

  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
  1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,   1,  1,  1,  1,
};



 /*
 * Debug logging / Debug dummy wrappers 
 *
*/

/* output file for debugging */
#define DEBUG_LOG_FILE "/var/log/spf.log"

/* output file for transaction logging */
#define OUTPUT_LOG_FILE "/var/log/spflog.txt"

#if defined _SPF_DEBUG
#define dbg_printf _printf_dbg
#define dbg_pprintf _pprintf_dbg
#endif

#ifndef _SPF_DEBUG
#define dbg_printf _dummy_debug
#define dbg_pprintf _dummy_pdebug
#endif



 /*
 *  function declarations
 *
*/


 /*
 * Debugging
 *
*/
void _printf_dbg(const u_int8_t, const char *, const char *, const size_t, 
  const char *, ...);

void _pprintf_dbg(const u_int8_t, const char *, const char *, const size_t,
  const char *);

void _dummy_debug(const u_int8_t, const char *, const char *, const size_t,
  const char *, ...);

void _dummy_pdebug(const u_int8_t, const char *, const char *, const size_t,
  const char *);


 /*
 * Memory allocation / deallocation
 *
*/

void *UTIL_malloc(const int32_t, const char *, const int32_t, const char *);
void *UTIL_realloc(void *, const int32_t, const char *, const int32_t, const char *);
void  UTIL_free(void *, const char *, const int32_t, const char *);


 /*
 * String handling / SPF query handling (string related)
 *
*/

void      UTIL_log_result(peer_info_t *);
char     *UTIL_get_date(void);
char     *UTIL_strndup(const char *, const size_t);
char     *UTIL_strdup(const char *);
int16_t   UTIL_index(const char *, const char);
char     *UTIL_split_str(const char *, const char, const u_int8_t);
char     *UTIL_split_strr(const char *, const char, const u_int8_t);
u_int8_t  UTIL_count_delim(const char *, const char);
SPF_BOOL  UTIL_is_spf_delim(const char);
SPF_BOOL  UTIL_is_spf_result(const char);
SPF_BOOL  UTIL_is_macro(const char *);


 /*
 * SPF Mechanism parsing
 *
*/

SPF_BOOL  UTIL_mx_cmp(peer_info_t *, const char *, const int8_t);
SPF_BOOL  UTIL_a_cmp(peer_info_t *, const char *, const int8_t);
SPF_BOOL  UTIL_ptr_cmp(peer_info_t *, const char *);


 /*
 * General utility
 *
*/

SPF_MECHANISM UTIL_get_policy_mech(const char *);
SPF_RESULT    UTIL_get_mech_prefix(peer_info_t *, const char *);
SPF_BOOL      UTIL_assoc_prefix(peer_info_t *, SPF_RESULT, const char *);
policy_addr_t *UTIL_expand_ip(const char *);
SPF_BOOL      UTIL_is_spf_delim(const char);
SPF_BOOL      UTIL_is_sid(const char *);
SPF_BOOL      UTIL_is_ip(const char *);


 /*
 * DNS related parsing 
 *
*/

char     *UTIL_rev_addr(const char *);
char     *UTIL_get_dname(const char *);
SPF_BOOL  UTIL_cidr_cmp(const policy_addr_t *, const struct in_addr *);
SPF_BOOL  UTIL_validate_ptr(peer_info_t *);
SPF_BOOL  UTIL_validate_hostname(peer_info_t *, const char *, const int8_t);
char     *UTIL_url_encode(const char *);
char     *UTIL_reverse(const char *, const char);
SPF_BOOL  UTIL_addnode(split_str_t *, const char *, SPF_BOOL);
SPF_BOOL  UTIL_delnode(split_str_t *, const char *);


 /*
 * Threading (linux pthreads)
 *
*/

void _UTIL_pthread_mutex(void *, SPF_BOOL);


#ifdef _WITH_PTHREADS

/* pthreads utility mutex (used by debugging and date/time) */
extern pthread_mutex_t util_mutex;

#else

/* pthreads utility mutex dummy wrapper */
extern void *util_mutex; 

#endif /* _WITH_PTHREADS */


#ifdef  HAVE__BEGIN_DECLS
__END_DECLS /* _UTIL_H */
#else
# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */

#endif /* _UTIL_H */

/* end util.h */
