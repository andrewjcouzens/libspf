/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  FILE: dns.h
*  DESC: dns functions header file
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

#ifndef _DNS_H
#define _DNS_H 1

#include "../../config.h"    /* autoconf */
#include <stdio.h>           /* printf */
#include <string.h>          /* snprintf strstr */
#include <strings.h>         /* strcasecmp */
#include <sys/socket.h>      /* inet_ functions / structs */
#include <netinet/in.h>      /* inet_ functions / structs */
#include <arpa/nameser.h>    /* DNS HEADER struct */
#include <resolv.h>          /* dn_skipname */
#include <netdb.h>           /* gethostbyname */
#include <arpa/inet.h>       /* in_addr struct */

#ifdef _WITH_DARWINPPC
#include <nameser8_compat.h> /* T_CNAME */
#endif /* _WITH_DARWINPCC */

#ifdef HAVE_PTHREAD_H
#include <pthread.h>         /* pthread_mutex_t */
#endif /* HAVE_PTHREAD_H */

#ifndef T_SPF
# define T_SPF 99
#endif

#ifdef HAVE__BEGIN_DECLS
__BEGIN_DECLS
#else
# ifdef __cplusplus
extern "C" {
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */

/*
*  For reference purposes commented out are the constants based on
*  RFC 883, RFC 1034, RFC 1035.  Because we're working with IN_TXT
*  records we will use a larger packet size at 65536 bytes which
*  is likey to cover most circumstances.
*
*  #define PACKETSZ  512   max response packet size
*  #define MAXDNAME  1025  max uncompressed IN_TXT record
*  #define MAXCDNAME 255   max compressed IN_TXT record
*
*/

#define SPF_PACKETSZ  8192
#define SPF_MAXDNAME  1025
#define SPF_MAXCDNAME 255

extern int h_errno;

#ifndef HPUX
struct hostent;
#endif /* HPUX */

void _DNS_gethostbyname_r_free(void);

/* if we've got native gethostbyname_r (GNU extension) */
#ifdef HAVE_GETHOSTBYNAME_R

  struct hostent *_DNS_GNU_gethostbyname_r(const char *name, struct hostent *result,
    char *buf, int buflen, int *h_errnop);

  #define xgethostbyname(a, b, c, d, e) _DNS_GNU_gethostbyname_r((a), (b), (c), (d), (e))
  #define xgethostbyname_free()

#else

  #ifdef HAVE_PTHREAD_H

    extern pthread_mutex_t dns_mutex;

    struct hostent *_DNS_gethostbyname_r(const char *name, struct hostent *result,
      char *buf, int buflen, int *h_errnop);

    #define xgethostbyname(a, b, c, d, e) _DNS_gethostbyname_r((a), (b), (c), (d), (e))
    #define xgethostbyname_free()         _DNS_gethostbyname_r_free()

  #else
    #define xgethostbyname(a, b, c, d, e) gethostbyname((a))
    #define xgethostbyname_free()
  #endif /* HAVE_PTHREAD_H */

#endif /* HAVE_GETHOSTBYNAME_R */

/* silence link error on SCO */
#ifdef SCO
#undef h_errno
#define h_errno errno
#endif /* SCO */

char    *DNS_query(peer_info_t *, const char *, const int T_TYPE, const char *);
char    *DNS_txt_answer(int16_t, const u_char *, const u_char *, u_char *,
                        char *, int *);
char    *DNS_mx_answer(int16_t, const u_char *, const u_char *, u_char *,
                       char *, int *);
SPF_BOOL DNS_ptr_answer(peer_info_t *, int16_t, const u_char *, const u_char *,
                        u_char *, char *, const char *, int *);
char    *DNS_cname_answer(int16_t, const u_char *, const u_char *,
                          u_char *, char *, int *);
SPF_BOOL DNS_check_client_reverse(peer_info_t *);


#ifdef  HAVE__BEGIN_DECLS
__END_DECLS /* _DNS_H */
#else
# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */

#endif /* _DNS_H */

/* end dns.h */
