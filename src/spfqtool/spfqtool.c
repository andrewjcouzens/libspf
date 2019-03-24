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

#include "spfqtool.h"


/* SPF_usage
*
*  Author: James Couzens <jcouzens@6o4.ca>
*
*  Date:   07/04/04
*  Date:   07/28/04 - Renamed to spfqtool
*  Date:   09/08/04 - Added SPF_build_header call
*
*  Desc:
*         Main function, allocates memory and makes calls to the libSPF 
*  library which parses the "fake" query.
*
*/
int main(int argc, char *argv[])
{
  u_int8_t i = 0;                      /* utility */
  
  SPF_RESULT res = SPF_UNKNOWN;        /* libSPF result code */

  SPF_BOOL use_explain = SPF_FALSE;    /* T / F provide SPF Explanation */
  SPF_BOOL use_trusted = SPF_FALSE;    /* T / F attempt Trusted Forwarder */
  SPF_BOOL use_guess   = SPF_FALSE;    /* T / F attempt Best Guess */
  SPF_BOOL test_mode   = SPF_FALSE;    /* T / F enable test mode */

  char *margv   = NULL;                /* pointer to current argv element */
  char *ip      = NULL;                /* ip address to test connecting from */
  char *address = NULL;                /* email address to test sending from */
  char *helo    = NULL;                /* helo hostname to test sending from */
  char *tmp     = NULL;                /* utility pointer */
  char *buf     = NULL;                /* buffer to store generated SPF header */
   
  peer_info_t *pinfo = NULL;           /* libSPF peer_info structure */

  if (argc <= 1)
  {
    SPF_usage();

    return(SPF_FALSE);
  }

  for (i = 1; i < argc; i++)
  {
    tmp = argv[i];

    if (*tmp == '-')
    {
      margv = (tmp + 3);
      
      switch (*(tmp + 1))
      {
        /* best guess */
        case 'b' :
        {
          use_guess = atoi(margv);

          break;
        } /* 'b' */

        /* debug */
        case 'd' :
        {
          confg.level = atoi(margv);

          break;
        } /* 'd' */

        /* explanation */
        case 'e' :
        {
          use_explain = atoi(margv);

          break;
        } /* 'e' */

        /* RFC2821 HELO */
        case 'h' :
        {
          helo  = strdup(margv);

          break;
        } /* 'h' */

        /* ip address */
        case 'i' :
        {
          ip  = strdup(margv);

          break;
        } /* 'i' */

        /* source email address */
        case 's' :
        {
          address = strdup(margv);

          break;
        } /* 's' */

        /* trusted forwarder */
        case 't' :
        {
          use_trusted = atoi(margv);

          break;
        } /* 't' */

        /* version */
        case 'v' :
        {
          printf("SPF Query Tool v%s - James Couzens <jcouzens@codeshare.ca>\n\n", 
            SPFQTOOL_VERSION);

          return(0);
        } /* 'v' */

        /* test mode */
        case 'z' :
        {
          test_mode = SPF_TRUE;

          break;
        } /* 'z' */

        default:
        {
          break;
        } /* default */
      }
    }
  } /* for */
 
  if (ip == NULL)
  {
    printf("You need to specify an IP Address to test against\n\n");

    SPF_usage();

    free(address);

    return(SPF_FALSE);
  }
  else if (address == NULL)
  {
    printf("You need to specify a from email address\n\n");
    
    SPF_usage();

    free(ip);

    return(SPF_FALSE);
  }
  else if (helo == NULL)
  {
    helo = strdup(HELO_HOST);

    printf("You didn't give me a helo host, using (%s)\n", helo);
  }

  if (confg.level >= 1)
  {
    printf("SPF Query Tool v%s - James Couzens <jcouzens@codeshare.ca>\n", 
      SPFQTOOL_VERSION);
   
    printf("[DEBUG]: Debugging level:    %u\n", confg.level);
    printf("[DEBUG]: RFC2821 Mail From:  %s\n", address);
    printf("[DEBUG]: RFC2821 HELO:       %s\n", helo);
    printf("[DEBUG]: Purported address:  %s\n", ip);

    printf("[DEBUG]: SPF Explanation:    %s\n",
      use_explain ? "Enabled" : "Disabled");

    printf("[DEBUG]: Trusted Forwarder:  %s\n",
      use_trusted ? "Enabled" : "Disabled");

    printf("[DEBUG]: Best Guess:         %s\n",
      use_guess ? "Enabled" : "Disabled");

    printf("\n");
  }
  
  if ((pinfo = SPF_init(helo, ip, NULL, NULL, NULL,
                        use_trusted, use_guess)) != NULL)
  {
    /* perform fake HELO */
    SPF_smtp_helo(pinfo, helo);
    
    /* perform fake MAIL FROM */
    SPF_smtp_from(pinfo, address);
    
    /* assign and perform SPF parse */
    pinfo->RES = SPF_policy_main(pinfo);
    res        = pinfo->RES;

    free(address);
    free(helo);
    free(ip);
 
    /* print the results of the query.  The NULL check on the output is
     * to the benefit of SOLARIS users where printf is unable to handle
     * a NULL variable.  Linux users can omit this check. 
     */

    if (test_mode != SPF_TRUE)
    {
      printf("SPF short result:   %s\n",
        pinfo->rs ? pinfo->rs : "NULL");

      printf("SPF verbose result: %s\n",
        pinfo->error ? pinfo->error : "NULL");
    }
    else
    {
      printf("%s\n%s\n%s\n", 
        pinfo->rs      ? pinfo->rs      : "NULL",
        pinfo->error   ? pinfo->error   : "NULL",
        pinfo->explain ? pinfo->explain : "NULL");
    }

    if (use_explain == SPF_TRUE)
    {
      buf = SPF_get_explain(pinfo);

      printf("SPF explanation:    %s\n",
        pinfo->explain ? pinfo->explain : "NULL");

      free(buf);
    }

    /* for the tests we need to be silent :-) */
    if (test_mode != SPF_TRUE)
    {
      if (use_trusted == SPF_TRUE)
      {
        printf("Trusted Forwarder:  Attempted.\n");
      }
   
      if (use_guess == SPF_TRUE)
      {
        printf("Best Guess:         Attempted.\n");
      }

      if ((buf = SPF_build_header(pinfo)) != NULL)
      {
        printf("RFC2822 header:     %s\n", buf);
        free(buf);
      }
    }

    /* close SPF session (free memory associated with parse) */
    SPF_close(pinfo);
  }   
 
/* 
  free(buf);
  free(pinfo);
 */
  return(SPF_FALSE); 
}


/* SPF_usage
*
*  Author: James Couzens <jcouzens@6o4.ca>
*
*  Date:   12/25/03
*  Date:   07/28/04 - Renamed to spfqtool
*
*  Desc:
*         Displays usage help information when the binary is called with
*  no arguments.
*
*/
void SPF_usage()
{
  printf("spfqtool usage:\n");
  printf("\n");
  printf("spfqtool [b|d|e|i|s|t|h|v]\n");
  printf("\n");
  printf("-b [0,1]   - Enable Best Guess support (True (0) or False (1))\n");
  printf("-d [x]     - DEBUG where x is a number between 1 and 255\n");
  printf("-e [0,1]   - Enable SPF explanation (True (0) or False (1))\n");
  printf("-h [host]  - HELO hostname to test with\n");
  printf("-i [addr]  - IP Address where the fake connection will come from\n");
  printf("-s [email] - What email address to test with\n");
  printf("-t [0,1]   - Enable Trusted Forwarder support (True (0) or False (1))\n");
  printf("-v         - Display version string\n");
  printf("\n");
  printf("Example: ./spfqtool -i 10.0.0.2 -s jcouzens@6o4.ca -h spftools.net\n");
  printf("\n");
  printf("Minimum required arguments are 'i', and 's'\n");
  printf("\n");

  return;
}

/* end spfqtool.c */
