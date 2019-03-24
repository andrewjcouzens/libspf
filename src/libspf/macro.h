/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  FILE: macro.h
*  DESC: macro functions header file 
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


#ifndef	_MACRO_H
#define	_MACRO_H 1

#include <stdio.h>        /* stdin / stdout */
#include <stdlib.h>       /* malloc / free */
#include <string.h>       /* strstr / strdup */
#include <ctype.h>        /* isupper / tolower */

#include "../../config.h" /* autoconf */
#include "spf.h"

#ifdef  HAVE__BEGIN_DECLS
__BEGIN_DECLS
#else
# ifdef __cplusplus
extern "C" {
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */


char      *MACRO_expand(peer_info_t *peer_info, const char *s);
char      *MACRO_process(peer_info_t *peer_info, char *macro, const size_t size);
char      *MACRO_eatmore(char *macro, char *s);
SPF_BOOL  MACRO_addbuf(strbuf_t *master, char *s, const size_t size);


#ifdef  HAVE__BEGIN_DECLS
__END_DECLS /* _MACRO_H */
#else
# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* HAVE__BEGIN_DECLS */

#endif /* _MACRO_H */

/* end macro.h */
