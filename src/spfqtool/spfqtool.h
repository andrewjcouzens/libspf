/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  File:   spfqtool.c
*  Desc:   SPF Query Tool (an example implementation of libSPF)
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
 
#ifndef _SPF_QTOOL_H
#define _SPF_QTOOL_H 1

#include "../../config.h"             /* autoconf */
#include <stdio.h>                    /* printf */
#include <stdlib.h>                   /* malloc  */
#include <string.h>                   /* free */
#include "../libspf/spf.h"            /* libSPF */
#include "../libspf/_stdint.h"        /* our stdint header */


#ifdef  __BEGIN_DECLS
__BEGIN_DECLS
#else
# ifdef __cplusplus
extern "C" {
# endif /* __cplusplus */
#endif /* __BEGIN_DECLS */

#define SPFQTOOL_VERSION  "0.4"           /* version */
#define HELO_HOST         "nobody"        /* default HELO host if none */
#define HOSTNAME          "libspf.org"    /* hostname */
 
int main(int argc, char *argv[]);
void SPF_usage();

#ifdef  __BEGIN_DECLS
__END_DECLS
#else
# ifdef __cplusplus
}
# endif /* __cplusplus */
#endif /* __BEGIN_DECLS */

#endif /* _SPF_QTOOL_H */

/* end spfqtool.h */
