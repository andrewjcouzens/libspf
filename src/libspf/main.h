/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  FILE: spf.h
*  DESC: main library header file
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


#ifndef	_MAIN_H
#define	_MAIN_H 1

#include <stdio.h>                /* stdin / stdout */
#include <stdlib.h>               /* malloc / free */
#include <string.h>               /* strstr / strdup */
#include <stdarg.h>               /* va_snprintf */

/*
#ifdef _WITH_OPENBSD
#include <inttypes.h> */          /* uintptr_t */
/*#endif*/ /* _WITH_OPENBBSD */

#include "../../config.h"         /* autoconf */
#include "_stdint.h"              /* our stdint */
#include "spf.h"


#ifdef  HAVE__BEGIN_DECLS
__BEGIN_DECLS
#else
# ifdef __cplusplus
extern "C" {
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */

#define FL_A   2    /* normal debugging */
#define FL_B   4    /* verbose debugging */
#define FL_C   8    /* normal and verbose debugging */
#define FL_D  16    /* xepprintf and xpprintf results */
#define FL_E  32    /* normal debug + profile results */
#define FL_F  64    /* verbose debug + profile results */
#define FL_G 128    /* normal + verbose + profile results */


/* # limiting recursion */
#ifdef _RFC_RECURSION
#define SPF_MAX_RECURSE 20 
#else
#define SPF_MAX_RECURSE 10
#endif /* _RFC_RECURSION */


/* spf MTA result strings */
#define RES_PASS    "domain of %s designates %s as permitted sender\r\n"
#define RES_NONE    "domain of %s does not designate permitted sender " \
                    "hosts\r\n"
#define RES_S_FAIL  "transitioning domain of %s does not designate %s " \
                    "as permitted sender\r\n"
#define RES_H_FAIL  "domain of %s does not designate %s as permitted " \
                    "sender\r\n"
#define RES_ERROR   "encountered temporary error during SPF processing " \
                    "of %s\r\n"
#define RES_NEUTRAL "%s is neither permitted nor denied by domain of " \
                    "%s\r\n"
#define RES_UNKNOWN "error in processing during lookup of %s\r\n"
#define RES_UNMECH  "encountered unrecognized mechanism during SPF " \
                    "processing of domain of %s\r\n"

/* header strings */
#define HDR_PASS    "Received-SPF: pass (%s: domain of %s designates " \
                    "%s as permitted sender) receiver=%s; client_ip=%s; " \
                    "envelope-from=%s;"

#define HDR_NONE    "Received-SPF: none (%s: domain of %s does not " \
                    "designate permitted sender hosts)"

#define HDR_S_FAIL  "Received-SPF: softfail (%s: domain of " \
                    "transitioning %s does not designate %s as " \
                    "permitted sender) receiver=%s; client_ip=%s; " \
                    "envelope-from=%s;"

#define HDR_H_FAIL  "Received-SPF: fail (%s: domain of %s does not " \
                    "designate %s as permitted sender) receiver=%s; " \
                    "client_ip=%s; envelope-from=%s;"

#define HDR_ERROR   "Received-SPF: error (%s: error in processing " \
                    "during lookup of %s: DNS timeout)"

#define HDR_NEUTRAL "Received-SPF: neutral (%s: domain of %s is " \
                    "neutral about designating %s as permitted sender)"

#define HDR_UNKNOWN "Received-SPF: unknown (%s: domain of %s " \
                    "encountered an error while parsing (check SPF " \
                    "record %s for errors))"

#define HDR_UNMECH  "Received-SPF: unknown -extension:%s (%s: domain of " \
                    "%s uses a mechanism not recognized by this client)"

/* Deal with systems where these types are not used and define them where
*  they are found to be missing
*/
/*#ifndef HAVE_U_INT8_T
# ifdef HAVE_UINT8_T
typedef uint8_t u_int8_t;
# else
typedef unsigned char u_int8_t;
# endif*/ /* HAVE_UINT8_T */
/*#endif *//* HAVE_U_INT8_T */
/*
#ifndef HAVE_U_INT16_T
# ifdef HAVE_UINT16_T
typedef uint16_t  u_int16_t;
# else
typedef unsigned int  u_int16_t;
# endif*/ /* HAVE_UINT16_T */
/*#endif*/ /* HAVE_U_INT16_T */

/*#ifndef HAVE_U_INT32_T
# ifdef HAVE_UINT32_T
typedef uint32_t  u_int32_t;
# else
typedef unsigned int  u_int32_t;
# endif*/ /* HAVE_UINT32_T */
/*#endif*/ /* HAVE_U_INT32_T */

/*#ifndef HAVE_UINTPTR_T
typedef unsigned long int  uintptr_t;
#endif*/ /* HAVE_UINTPTR_T */


/*  Main library functions (main.c) */
peer_info_t *SPF_init(const char *, const char *, const char *, const char *,
                      const char *, u_int32_t, u_int32_t);
SPF_BOOL     SPF_smtp_helo(peer_info_t *, const char *);
SPF_BOOL     SPF_smtp_from(peer_info_t *, const char *);
SPF_RESULT   SPF_policy_main(peer_info_t *);
SPF_BOOL     SPF_parse_policy(peer_info_t *, const char *);
SPF_RESULT   SPF_fetch_policy(peer_info_t *, const char *);
char        *SPF_result(peer_info_t *);

char        *SPF_build_header(peer_info_t *);
char        *SPF_get_explain(peer_info_t *);
peer_info_t *SPF_close(peer_info_t *);



 /*
 * private functions
 *
*/

/*
static SPF_BOOL    _SPF_pre_parse_policy(const char *);
static SPF_RESULT  _SPF_fetch_policy(peer_info_t *p, const char *record);
static SPF_BOOL    _SPF_clear_holdbufs(peer_info_t *p);
*/



/*
static SPF_BOOL _SPF_clear_holdbufs(peer_info_t *);
*/



#ifdef  HAVE__BEGIN_DECLS
__END_DECLS /* _MAIN_H */
#else
# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */


#endif /* main.h */
