/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau   <scomeau@obscurity.org>
*
*  File:   main.c
*  Desc:   Main library functionality
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

#ifdef _WITH_PTHREADS

  #include <pthread.h>       /* pthread_mutex */

#endif /* _WITH_PTHREDS */

#include "main.h"            /* our header */
#include "util.h"            /* Utility functions */
#include "dns.h"             /* DNS functions */
#include "macro.h"           /* MACRO parsing functions */

#undef VERSION               /* autoconf */

spf_config_t confg;          /* global config struct */

int h_errno;                 /* error handling */

#ifdef _WITH_PTHREADS

  /* mutex for _DNS_gethostbyname_r wrapper */
  extern pthread_mutex_t dns_mutex;

#endif /* _WITH_PTHREADS */

/* 
* private function declarations
*
*/
static SPF_BOOL   _SPF_pre_parse_policy(const char *);
static SPF_RESULT _SPF_fetch_policy(peer_info_t *p, const char *);
static SPF_BOOL   _SPF_clear_holdbufs(peer_info_t *);


/* SPF_init
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/25/03
*
*  Desc:
*         Applies config options and returns allocated memory to a peer_info_t
*  structure.  Malloc returns NULL on a failure, and as such this function exits
*  with NULL upon failure to allocate memory which there by results in a
*  complete failure of the entire library.
*
*  Return:
*         A pointer to a newly allocated peer_info structure.  Although
*  SPF_close() states that the caller does do this, this is perceived through
*  the fact that the caller does indeed have to allocate a pointer of the 
*  peer_info_t variety and thus by calling us, we're simply providing the
*  internal filling.  This library both allocates the interal parts of a 
*  peer_info structure, and frees it (SPF_close).  However the caller is 
*  still responsible to do away with this pointer reference.
*
*/
peer_info_t *SPF_init(const char *local, const char *rip, const char *expl,
  const char *tf, const char *guess, u_int32_t use_trust, u_int32_t use_guess)
{
  time_t curtime = {0};         /* time */

  char *cur_utc_time = NULL;    /* time */

  peer_info_t *p = NULL;        /* return structure buffer */


   /*
   *  spf_result struct including header texts.  This structure is used
   *  during message header generation and has intended future purposes.
   *  Each string has associated with it, its actual size which is used
   *  to provide some measure of protection against overflowing the strings
   *  as they are (currently) statically defined in util.h
  */
  static spf_result_t spf_result[] =
  {{SIZEOF(HR_PASS),    HR_PASS,    SPF_PASS,    SIZEOF(HDR_PASS),    HDR_PASS,    '+' },
   {SIZEOF(HR_NONE),    HR_NONE,    SPF_NONE,    SIZEOF(HDR_NONE),    HDR_NONE,    '\0'},
   {SIZEOF(HR_S_FAIL),  HR_S_FAIL,  SPF_S_FAIL,  SIZEOF(HDR_S_FAIL),  HDR_S_FAIL,  '~' },
   {SIZEOF(HR_H_FAIL),  HR_H_FAIL,  SPF_H_FAIL,  SIZEOF(HDR_H_FAIL),  HDR_H_FAIL,  '-' },
   {SIZEOF(HR_ERROR),   HR_ERROR,   SPF_ERROR,   SIZEOF(HDR_ERROR),   HDR_ERROR,   '\0'},
   {SIZEOF(HR_NEUTRAL), HR_NEUTRAL, SPF_NEUTRAL, SIZEOF(HDR_NEUTRAL), HDR_NEUTRAL, '?' },
   {SIZEOF(HR_UNKNOWN), HR_UNKNOWN, SPF_UNKNOWN, SIZEOF(HDR_UNKNOWN), HDR_UNKNOWN, '\0'},
   {SIZEOF(HR_UNMECH),  HR_UNMECH,  SPF_UNMECH,  SIZEOF(HDR_UNMECH),  HDR_UNMECH,  '\0'}};

   /*
   * This structure here is the heart and soul or effectively the 'context'
   * of libSPF.  This structure is passed back and forth between nearly
   * every function which will operate on it in one way or another.
  */
  p = xmalloc(SIZEOF(peer_info_t));

  p->spf_result = spf_result;


   /*
   * Set the SPF query recursion level to zero.  This counter is
   * incremeneted to a maximum of SPF_MAX_RECURSE (default value of
   * that macro is 20) to provide a limit of recursiveness.  Not only does
   * it astound me to see people creating infinite loops unintentionally
   * through the use of the 'include' and 'redirect' facilities within SPF,
   * but there is also the greater than average chance that a skriptkiddie
   * or some other individual with malicious intentions would use a lack of
   * such a level (or a poorly set one, you REALLY should not raise this
   * above 20) to faciliate a very effective DoS or dDoS attack against your
   * server using SPF checks.
  */
  p->spf_rlevel = 0;

   /*
   * RFC2821 (pre-DATA) related variables
  */

  p->helo = NULL;
  p->ehlo = NULL;
  p->from = NULL;

  if (local != NULL && (*local && *(local + 1)))
  {
    p->mta_hname = xstrndup(local, SPF_MAX_LOCAL_PART);
    p->r_vhname  = xstrndup(local, SPF_MAX_LOCAL_PART);
  }
  else
  {
    p->mta_hname = NULL;
    p->r_vhname  = NULL;
    xepprintf("Warning: Invalid local-part detected (DSN or NULL?)\n");
  }

  /* don't change this, this is for Solaris which can't print NULL strings */
  xvprintf("Called with: [%s] [%s] [%s] [%s] [%s] %u:%u\n",
     local ? local : "NULL",
     rip   ? rip   : "NULL",
     expl  ? expl  : "NULL",
     tf    ? tf    : "NULL",
     guess ? guess : "NULL",
     use_trust, use_guess);

   /*
   * Set the default SPF version level to zero.  This is important because
   * the lack of a valid SPF version here is relied upon within SPF_parse_policy
   * to determine an appropriate exit enforcing the RFC requirement that each
   * SPF record publish a valid version within their SPF query.
  */
  p->spf_ver = 0;

   /*
   * "Trusted Forwarder" enabled? This is also what you could use if you wanted
   * to operate an 'in-house' whitelist for your server. For more information
   * about the offical "Trusted Forwarder" service visit
   * http://trustedforwarder.org
  */
  if (use_trust == SPF_TRUE)
  {
    p->use_trust = SPF_TRUE;
  }
  else
  {
    p->use_trust = SPF_FALSE;
  }

   /*
   * "Best Guess" enabled?  This is a great way to provide a "generic" SPF check
   * against domains who do not publish SPF either through ignorance or refusal
   * to do so.  The default best guess is defined in spf.h and is comprised of
   * SPF syntax facilitating 'a', 'mx', and 'ptr' checks against the connected
   * host when enabled in an attempt to validate them
  */
  if (use_guess == SPF_TRUE)
  {
    p->use_guess = SPF_TRUE;
  }
  else
  {
    p->use_guess = SPF_FALSE;
  }

  p->ALL = SPF_FALSE;
  p->p   = NULL;

   /*
   * SPF Explanation.  This can be optionally pre-pended to the RFC2822
   * message body as a means of informing a client when rejecting their
   * message for a failure to appropriate pass a desired SPF level.
  */
  if (expl != NULL && (*expl && *(expl + 1)))
  {
    p->explain = xstrndup(expl, (strlen(expl) + 1));
  }
  else
  {
    p->explain = NULL;
  }

  if (guess != NULL && (*guess && *(guess + 1)))
  {
    p->guess = xstrndup(guess, (strlen(guess) + 1));
  }
  else
  {
    p->guess = xstrndup(SPF_GUESS, (SIZEOF(SPF_GUESS) + 1));
  }

  if ((tf != NULL) && (*tf && *(tf + 1)))
  {
    p->trusted = xstrndup(tf, (strlen(tf) + 1));
  }
  else
  {
    p->trusted = xstrndup(SPF_TRUSTED, (SIZEOF(SPF_TRUSTED) + 1));
  }

  p->ptr_mhost       = NULL;    /* MTA hostname */
  p->current_domain  = NULL;    /* Current domain name (of client) */
  p->original_domain = NULL;    /* Original domain name (of client) */
  p->cur_eaddr       = NULL;    /* Current email-address (of client) */
  p->cname_buf       = NULL;    /* Current CNAME value */
  p->redirect_buf    = NULL;    /* Current redirect value */
  p->include_set     = NULL;    /* Set of include directives */

   /*
   * inet_pton is used to convert the IP address of the remotely connected
   * client into a network address structure which will be used during
   * and SPF parse to perform CIDR calculations against a variety of SPF
   * mechanisms ('ip4', 'ip6', etc.).  Currently hard set for IPv4.
   *
   * A character version of the remote peer is retained within the
   * peer_info_t structure by reason that there is no sense not doign
   * so since we will need to reference it in a human readable form,
   * and since the MTA has already performed the labour necessary to
   * get it into this form, we might as well keep it.
  */
  if (((rip != NULL) && (*rip && *(rip + 1))) &&
       (inet_pton(AF_INET, rip,  &p->addr) >= 0))
  {
     p->r_ip = xstrndup(rip, SPF_MAX_IP_ADDR);
  }
  else
  {
    xepprintf("Warning: Unable to execute inet_print (bad passed ipaddr?)\n");
    SPF_close(p);

    return(NULL);
  }

   /*
   * 'ip_ver' is the Internet Address protocol version being used
   * at any given time during an SPF parse.  Whilst this is intended to
   * support IPv6 at this time it is hard set to IPv4 (AF_INET)
  */
  snprintf(p->ip_ver, SPF_MAX_IP_ADDR, "in-addr");

   /*
   * Obtain the number of seconds since the UNIX Epoch or UTC time
   * which we may optionally be used when pre-pending the Received-SPF
   * header after an SPF parse
  */
  cur_utc_time = xmalloc(SPF_MAX_DATETIME);
  snprintf(cur_utc_time, SPF_MAX_DATETIME, "%lu", time(&curtime));
  memcpy(p->utc_time, cur_utc_time, SPF_MAX_DATETIME);
  xfree(cur_utc_time);

   /*
   * As per the SPF RFC, localhost shall always be considered exempt from
   * any SPF checks.  There is no facility to override this, nor should
   * you.
  */
  if ((strcmp(rip, "127.0.0.1") == 0) || (strcmp(rip, "localhost") == 0))
  {
    UTIL_assoc_prefix(p, SPF_PASS, NULL);
  }
  else
  {
    UTIL_assoc_prefix(p, SPF_NEUTRAL, NULL);
  }

  /* assign the TXT portion NULL */
  p->txt = xmalloc(SPF_MAX_STR);

  xprintf("libspf initialized succesfully. (%i bytes allocated)\n",
    SIZEOF(peer_info_t));

  return(p);
}


/* SPF_close
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/25/03
*
*  Desc:
*          Free memory associated with passed peer_info_t structure.  p MUST
*  be nulled, checks in the various MTA code rely on it to be NULL for various 
*  external checks (not necessarily to just the functions within this file)
*
*  Return:
*          A pointer to a peer_info structure, specifically its a pointer to
*  the same peer_info structure that was passed to it.  This structure will 
*  now have been 'free' of all internal memory and can now its self be
*  free'd.  It is NOT free'd here by reason of consistency.  So you the 
*  implementor instantiated it, so to you shall destroy it.
*
*/
peer_info_t *SPF_close(peer_info_t *p)
{
  if (p == NULL)
  {
    xepprintf("peer structure null.  Aborting!\n");

    return(NULL);
  }

  xfree(p->mta_hname);
  xfree(p->helo);
  xfree(p->from);

  if ((p->spf_rlevel > 0) &&
      (p->current_domain != p->original_domain))
  {
    xfree(p->current_domain);
  }

  xfree(p->original_domain);
  xfree(p->r_ip);
  xfree(p->ptr_mhost);
  xfree(p->cur_eaddr);
  xfree(p->trusted);
  xfree(p->guess);
  xfree(p->explain);
  xfree(p->r_vhname);
  xfree(p->txt);
  xfree(p);

  p = NULL;

  return(p);
}



/* SPF_policy_main
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/10/03
*  Date:   01/24/04 by James <jcouzens@codeshare.ca>
*  Date:   05/02/04 by Teddy <teddy@teddy.ch>
*
*  Desc:
*          This is our libraries 'main' function if you will.  From here 
*  _SPF_fetch_policy is called to deal with the dirty work (fetching the
*  actual record(s)) and returning the result of an SPF evaluation of the
*  obtained data.  _SPF_fetch_policy transparently calls SPF_parse_policy
*  so any implementation only has to worry about primarily this function.
*
*  Return:
*          One of the enumerated values possible of an SPF parse.  See
*  spf.h for a list of available results.
*
*/
SPF_RESULT SPF_policy_main(peer_info_t *peer)
{
  SPF_RESULT res = SPF_UNKNOWN;    /* default SPF result */


  if (peer == NULL)
  {
    xepprintf("Unable to continue with a NULL peer_info_t structure!\n");

    return(SPF_UNKNOWN);
  }

  /* XXX: IPv6: ::1? */
  if ((strcmp(peer->r_ip, "127.0.0.1") == 0) ||
      (strcmp(peer->r_ip, "localhost") == 0))
  {
    xpprintf("localhost exempt from SPF checks; returning SPF_PASS\n");

    UTIL_assoc_prefix(peer, SPF_PASS, NULL);
    res = SPF_PASS;
  }
  else
  {
    /* make sure we start off neutral */
    UTIL_assoc_prefix(peer, SPF_NEUTRAL, NULL);

    /* try to get a result based on the info stored in peer */
    res = _SPF_fetch_policy(peer, NULL);

     /*
     * if we couldn't get a PASS explicitly, try trusted forwarder if it was
     * requested of us
    */
    if ((res != SPF_PASS) && (peer->use_trust == SPF_TRUE))
    {
      if (peer->trusted != NULL)
      {
        xpprintf("Failed to get SPF_PASS, trying trusted forwarder\n");

        res = _SPF_fetch_policy(peer, peer->trusted);
      }
    }

     /*
     * if we couldn't get a PASS from trusted forwarder either, try best guess
     * if it was requested of us
    */
    if ((res != SPF_PASS) && (peer->use_guess == SPF_TRUE))
    {
      if (peer->guess != NULL)
      {
        xpprintf("Failed to get SPF_PASS, trying best guess\n");

        res = _SPF_fetch_policy(peer, peer->guess);
      }
    }
  }

  xvprintf("Returning SPF_RESULT %i\n", res);

  return(res);
}


/* _SPF_fetch_policy
*
*  Author: Travis Anderson <tanderson@codeshare.ca>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   21/09/04
*
*  Desc:
*          Fetches the SERVER_POLICY records from the FQDN's NS server
*  and returns an SPF_RESULT enumeration indicating the level of
*  compliance with an SPF policy (match, fail, error etc.. see spf.h)
*  If record != NULL, it is used rather than make a DNS query.  This
*  function also manages SPF query recursion in all of its forms (CNAME,
*  include, redirect) such that when it finally returns to its original
*  caler, we'll have either hit the ceiling for max number of recursions,
*  exhausted all of the extraneous queries, or got an SPF_PASS.
*
*  Much of the functionality seen here (for early users of this library)
*  will seem familiar as it is what was previously all handled within one
*  main function (SPF_policy_main).  Travis and I sat down and hashed out
*  this better design which cleanly doesn't break the existing API and 
*  enables us to properly handle not only some of the ambigous elements of 
*  the RFC not previously understood (how INCLUDE and REDIRECT were to be
*  handled for example) but also to handle recursion properly. 
*
*  Return:
*          One of the enumerated values possible of an SPF parse.  See
*  spf.h for a list of available results.
*
*/
static SPF_RESULT _SPF_fetch_policy(peer_info_t *p, const char *record)
{
  SPF_RESULT res = SPF_UNKNOWN;       /* result of an SPF parse */

  char *rr_data      = NULL;          /* DNS query result */
  char *tmp          = NULL;          /* temporary pointer */
  char *cname_buf    = NULL;          /* tmp cname placeholder */
  char *redirect_buf = NULL;          /* tmp redirect placeholder */
 
  split_str_t *include_set = NULL;    /* tmp linked list of include directives */

  split_str_node_t *n = NULL;         /* node ptr for include_set */


  if (p == NULL)
  {
    xepprintf("Unable to continue with a NULL peer_info_t structure!\n");

    return(SPF_UNKNOWN);
  }

  if (p->spf_rlevel > SPF_MAX_RECURSE)
  {
    xvprintf("recursion level exceeded (%u) levels; Aborting.\n",
      p->spf_rlevel);

    return(SPF_UNKNOWN);
  }
  else
  {
    /* increment recursion count */
    p->spf_rlevel++;
  }

  xvprintf("[%i] current domain: [%s]\n", p->spf_rlevel, p->current_domain);
  xvprintf("[%i] redirect buffer: [%s]\n", p->spf_rlevel, p->redirect_buf);

  if (p->include_set != NULL)
  {
    xvprintf("[%i] include buffer size: (%i)\n", p->spf_rlevel,
      p->include_set->elements);
  }

  /* make sure we start fresh */
  _SPF_clear_holdbufs(p);

  if (record == NULL)
  {
    unsigned char t;
    /* try to get a TXT record, as usual */
    if ((rr_data = DNS_query(p, p->current_domain, t = T_SPF, NULL)) == NULL)
         rr_data = DNS_query(p, p->current_domain, t = T_TXT, NULL);
    if (rr_data != NULL)
    {
      xprintf("DNS_query returned with %s answer: [%s]\n", (t == T_SPF) ? "SPF" : "TXT", rr_data);

      if (_SPF_pre_parse_policy(rr_data) == SPF_TRUE)
      {
        xpprintf("DNS answer appears to be an SPF record\n");

        SPF_parse_policy(p, rr_data);

        xfree(rr_data);
      }
      else
      {
        xpprintf("DNS answer does not appear to be an SPF record\n");

        UTIL_assoc_prefix(p, SPF_NONE, NULL);

        xfree(rr_data);

        return(SPF_NONE);
      }
    }

     /*
     * if we weren't supplied a record by the caller, we try to fetch one
     * based on the information in peer
    */
    else if ((rr_data = DNS_query(p, p->current_domain, T_CNAME, NULL)) != NULL)
    {
      xvprintf("domain [%s] is CNAME of [%s]. Storing CNAME for recursion\n",
        p->current_domain, rr_data);

      p->cname_buf = rr_data;
    }
  }
  else
  {
    /*
     * record is used for things like trusted forwarder and best guess, so we
     * of course have to sidestep the DNS lookup to get to this point
    */
    xprintf("Was given overriding record: [%s]\n", rr_data);

    SPF_parse_policy(p, record);
  }

  if (p->RES == SPF_PASS)
  {
    /* we passed; we need not continue */
    xpprintf("Got SPF_PASS, returning\n");

    _SPF_clear_holdbufs(p);

    return(p->RES);
  }

  xvprintf("Result of SPF parse is %i\n", p->RES);

  /* store these here for now, we'll take them back later on */
  cname_buf    = p->cname_buf;
  redirect_buf = p->redirect_buf;
  include_set  = p->include_set;
  tmp          = p->current_domain;

  if ((cname_buf == NULL) && (include_set == NULL) && (redirect_buf == NULL))
  {
    /* we didn't pass and we've got nowhere else to turn, so leave */
    xpprintf("Didn't get SPF_PASS, and no CNAMEs/includes/redirects to turn"
             " to.  Returning.\n");

    return(p->RES);
  }

  xvprintf("tmp is holding the current domain: [%s]\n", tmp);

  /* reset context */
  p->cname_buf      = NULL;
  p->redirect_buf   = NULL;
  p->include_set    = NULL;
  p->current_domain = NULL;

   /*
   * First the CNAME is looked at, and separate from the 'include' and
   * 'redirect' buffer placeholders because its not possible to have either 
   * 'include' or 'redirect' if you have a CNAME!
  */
  if (cname_buf != NULL)
  {
    p->current_domain = cname_buf;

    xvprintf("Current domain: [%s]; CNAME Buffer: [%s]\n",
      p->current_domain, cname_buf);

    res = _SPF_fetch_policy(p, NULL);
  }
  else
  {
     /*
     * In the event that during our original parse we happend upon either the 
     * 'include' or 'redirect' markers, we would have saved their  contents in
     * the placeholder buffer within the peer_info_t structure until after the 
     * entire other items within the SPF language have been exhausted.  Once 
     * this has taken place we perform a brand new parse with the contents of
     * either of the two buffers should they have any data.
    */
    if (include_set != NULL)
    {
      xvprintf("Number of elements in include list: %i\n",
         include_set->elements);

      n = include_set->head;
      while (n != NULL)
      {
        p->current_domain = n->s;

        xvprintf("[%i] current domain is now [%s] from INCLUDE\n",
          p->spf_rlevel, p->current_domain ? p->current_domain : "NULL");

        res = _SPF_fetch_policy(p, NULL);

        xvprintf("[%i] result of SPF parse was %i\n", p->spf_rlevel, res);

        if ((res == SPF_PASS) || (res == SPF_NONE))
        {
          break;
        }

        n = n->next;
      }
    }

     /*
     * The 'include_set' induced SPF parse may have resulted in an SPF_PASS
     * result.  In the event that it didn't we then examine the 'redirect_buf'
     * and send it off if necessary trying again with a brand new SPF query.
    */
    if (res == SPF_NONE)
    {
      xpprintf("INCLUDE resulted in SPF_NONE, returning UNKNOWN\n");

      res = SPF_UNKNOWN;

      UTIL_assoc_prefix(p, SPF_UNKNOWN, NULL);
    }
    else if ((res != SPF_PASS) && (redirect_buf != NULL))
    {
      p->current_domain = redirect_buf;

      xvprintf("current domain is now: [%s] from REDIRECT\n",
        p->current_domain);

      res = _SPF_fetch_policy(p, NULL);

      /*xvprintf("result of SPF parse was %i\n", p->RES);*/
      xvprintf("result of SPF parse was: [%i]\n", res);
    }
  }

  /* restore the domain we originally entered this func with */
  p->current_domain = tmp;

  xvprintf("restored current domain to its original: [%s]\n",
    p->current_domain);

  /* place the old values back, SPF_clear_holdbufs will free them safely */
  p->cname_buf    = cname_buf;
  p->redirect_buf = redirect_buf;
  p->include_set  = include_set;

  _SPF_clear_holdbufs(p);

  xvprintf("leaving function; returning with value: (%i)\n", res);

   /*
   * If logging is enabled this will write to a statistics log
   * at (by default) /var/log/spflog.txt where you can over time
   * get a good idea of how SPF performs on your network.
   *
  */
#ifdef _SPF_LOGFILE_STATS
    UTIL_log_result(p);
#endif /* _SPF_LOGFILE_STATS */

  return(p->RES);
}


/*  _SPF_pre_parse_policy
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   10/07/04
*
*  Desc:
*          This really isn't a pre-parse, its more of a validation of
*  the record to further save time during a parse.  What happens here
*  is that two checks are made, one on the beginning of the string,
*  and another to simply see if the string contains a valid SPF1
*  version tag anywhere within.
*
*  liBSPF is an on-the-fly parser and because of the way DNS ANSWERS
*  are concatenated in random order and a lack of desire on my part to
*  write code to "re-order" a DNS response, this check facilitates a
*  quick exit on our part in the event that the most fundamental piece
*  of information in an SPF record is missing or wrong, and that is the
*  version tag.
*
*  Return:
*          SPF_TRUE in the positive outcome of either check, and
*  SPF_FALSE in the event of a  negative outcome.
*
*/
static SPF_BOOL _SPF_pre_parse_policy(const char *policy)
{
  if ((*policy == 'v') &&
      (*(policy + 1) == '=') &&
      (*(policy + 2) == 's') &&
      (*(policy + 3) == 'p') &&
      (*(policy + 4) == 'f') &&
      (*(policy + 5) == '1'))
  {
    xvprintf("Returning with valid SPFv1 record: [%s]\n", policy);

    return(SPF_TRUE);
  }
  else if (strstr(policy, "v=spf1") != NULL)
  {
    xpprintf("Found SPFv1 version mechanism: [%s]\n");

    return(SPF_TRUE);
  }

  xpprintf("Returning NULL (not a valid SPF TXT record)\n");

  /* no valid SPFv1 record here */
  return(SPF_FALSE);
}


/*  SPF_parse_policy
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   12/19/03
*
*  Desc:
*          Parses the passed SPF record and interprets the policies
*  contained within it to decide if based on various comparisons against
*  r_ip (remote peer's ipaddress) whether or not it meets the SPF
*  policy.
*
*  This is the main parse code.  Its probably the longest section of code
*  found within this library but I have tried to keep it as short and 
*  sweet as possible.  Its (simply) a large switch statement with a case
*  to handle each of the various SPF mechanisms and modifiers in turn
*  calling upon utility functions (util.c) to handle the data in the 
*  correct manner so that it can be interpreted and then evaluated 
*  against the connecting peer's IP address. 
*
*  Return:
*          SPF_TRUE upon successful parse and SPF_FALSE upon failure.
*
*/
SPF_BOOL SPF_parse_policy(peer_info_t *p, const char *policy)
{
  SPF_RESULT TMP_RES;                 /* placeholder for 'exists' check */
  SPF_MECHANISM POLICY_TYPE;          /* SPF policy mechanism type */

  SPF_RESULT PREFIX_TYPE;             /* SPF mechanism prefix type */

  SPF_BOOL POLICY_MATCH;              /* T / F on a policy match */
  SPF_BOOL POLICY_ERROR;              /* T / F for errors to return early */

  int16_t pos   = 0;                  /* position in the policy */
  int16_t s_pos = 0;                  /* position in a policy token */

  size_t p_len = 0;                   /* length of passed policy string */

  char *copy      = NULL;             /* storage container for passed policy */
  char *cp        = NULL;             /* working pointer to passed policy */
  char *token     = NULL;             /* token pointer to piece of policy */
  char *token_ptr = NULL;             /* working pointer for token */
  char *tmp_ptr   = NULL;             /* temporary utility pointer */
  char *tmp_ptr2  = NULL;             /* 2nd temporary utility pointer */
  char *macro     = NULL;             /* expanded macro storage container */
  char *dnsq_res  = NULL;             /* result of 'exists' dns query */

  policy_addr_t *policy_ip = NULL;    /* ip address of a policy record */

  POLICY_MATCH     = SPF_FALSE;
  POLICY_ERROR     = SPF_FALSE;
  PREFIX_TYPE      = SPF_UNKNOWN;


  if ((policy == NULL) || (p == NULL))
  {
    xepprintf("Unable to continue called with NULL structure\n");

    return(SPF_FALSE);
  }

  if (p->spf_rlevel >= SPF_MAX_RECURSE)
  {
    xvprintf("recursion breach (%i levels); Terminated.\n",
      p->spf_rlevel);

    snprintf(p->error, SPF_MAX_ERROR, "Recursion loop, terminated.");

    UTIL_assoc_prefix(p, SPF_UNKNOWN, NULL);

    return(SPF_FALSE);
  }

  p_len = strlen(policy);

  xprintf("about to parse [%s] of len: %i [%s]\n",
    policy, p_len, p->spf_result[p->RES].s);

  /* allocate memory and assign working pointer for policy */
  cp = copy = xstrndup(policy, (p_len + 1));

  /* loops through the entire policy string until its exhausted */
  while (*cp)
  {
    /* skip white space */
    while ((*cp == ' ') && (*(cp + 1) == ' '))
    {
      cp++;
    }
    pos = UTIL_index(cp, ' ');

    if (!*(cp + 1))
    {
      xfree(copy);
      xpprintf("leaving function; nothing more to parse, returning SPF_TRUE\n");

      return(SPF_TRUE);
    }

    token     = xstrndup(cp, (pos + 1));
    token_ptr = token;
    s_pos     = 0;

    /* look for a mechanism modifier prefix */
    if (UTIL_is_spf_result(*token_ptr) ||
      (strncmp(token_ptr, "default", 7) == 0))
    {
      PREFIX_TYPE = UTIL_get_mech_prefix(p, token_ptr);

      snprintf(p->last_m, SPF_MAX_MECHANISM, "%s", token_ptr);

      if  (*token_ptr != 'd')
      {
        /* move ahead one because a prefix was specified */
        token_ptr++;
      }
    }
    else
    {
      snprintf(p->last_m, SPF_MAX_MECHANISM, "%s", token_ptr);

      PREFIX_TYPE = SPF_PASS;
    }

    /* figure out what sort of mechanism we're working with */
    POLICY_TYPE = UTIL_get_policy_mech(token_ptr);

    xprintf("SPF Policy Mechanism: %i (token: %s) (pos: %i)\n",
      POLICY_TYPE, token_ptr, pos);

    switch (POLICY_TYPE)
    {
       /*
       *  no policy set
      */
      case NO_POLICY:
      {
        break;
      } /* NO_POLICY */

       /*
       *  unrecognized mechanism
      */
      case UNMECH:
      {
        UTIL_assoc_prefix(p, SPF_UNMECH, NULL);

        xvprintf("Unrecognized mechanism [%s]; returning SPF_FALSE\n", token);

        xfree(token);
        xfree(copy);

        return(SPF_FALSE);
      } /* UNMECH */

       /*
       *  'version' mechanism
      */
      case VERSION:
      {
        xprintf("policy mechanism is version [%s]\n", token_ptr);

        if ((s_pos = UTIL_index(token_ptr, '=')) > 0)
        {
          token_ptr += (s_pos + 4); /* skip =spf */

          if (atoi(token_ptr) > SPF_VERSION)
          {
            UTIL_assoc_prefix(p, SPF_NONE, NULL);

            xfree(token);
            xfree(copy);

            return(SPF_FALSE);
          }

          p->spf_ver = atoi(token_ptr);

          xvprintf("SPF Version defined as: %u\n", p->spf_ver);
        }
        else
        {
           xvprintf("SPF version redefined! (%u)\n", p->spf_ver);
           UTIL_assoc_prefix(p, SPF_S_FAIL, NULL);

           xfree(token);
           xfree(copy);

           return(SPF_FALSE);
        }

        break;
      } /* VERSION */

       /*
       *  'all' mechanism
      */
      case ALL:
      {
        xprintf("policy mechanism is all [%s] policy: (%i)\n",
          token_ptr, POLICY_TYPE);

        UTIL_assoc_prefix(p, PREFIX_TYPE, NULL);
        POLICY_MATCH = SPF_TRUE;
        p->ALL       = SPF_TRUE;

        break;
      } /* ALL */

       /*
       *  'default' policy (this is legacy -- will be removed after 1.0
      */
      case DEFAULT:
      {
        xprintf("policy mechanism is default [%s] policy: (%i)\n",
          token_ptr, POLICY_TYPE);

        POLICY_MATCH = SPF_TRUE;
        p->ALL       = SPF_TRUE;

        break;
      } /* DEFAULT */

       /*
       *  'include' mechanism
      */
      case INCLUDE:
      {
        xprintf("policy mechanism is include [%s]\n", token_ptr);

        if ((tmp_ptr = strstr(token_ptr, ":")) != NULL)
        {
          tmp_ptr++;

          if (UTIL_is_macro(tmp_ptr) == SPF_TRUE)
          {
            xvprintf("this INCLUDE mechanism contained macros [%s]\n", tmp_ptr);

            macro = MACRO_expand(p, tmp_ptr);
          }

          xvprintf("storing INCLUDE [%s] for later...\n", tmp_ptr);

          if (p->include_set == NULL)
          {
            xpprintf("Allocating new include_set\n");
            p->include_set    = xmalloc(SIZEOF(split_str_t));

            p->include_set->head     = NULL;
            p->include_set->tail     = NULL;
            p->include_set->elements = 0;
          }

          if (macro != NULL)
          {
            /* insert this translated instance of include onto the list */
            UTIL_addnode(p->include_set, macro, SPF_FALSE);
            xvprintf("Include size after insert: %i\n", p->include_set->elements);

            xfree(macro);
          }
          else
          {
            /* insert this instance of include onto the list */
            UTIL_addnode(p->include_set, tmp_ptr, SPF_FALSE);
            xvprintf("Include size after insert: %i\n", p->include_set->elements);
          }
        }
        else
        {
          /* 'include' with no options returns unknown */
          POLICY_MATCH = SPF_TRUE;
          UTIL_assoc_prefix(p, SPF_UNKNOWN, token_ptr);

          xfree(token);
          xfree(copy);

          return(SPF_TRUE);
        }

        break;
      } /* INCLUDE */

       /*
       *  'a' mechanism
      */
      case A:
      {
        xprintf("policy mechanism is A [%s]\n", token_ptr);

        if ((tmp_ptr = strstr(token_ptr, "/")) != NULL)
        {
          tmp_ptr++;
          POLICY_MATCH = UTIL_a_cmp(p, token_ptr, atoi(tmp_ptr));
        }
        else
        {
          POLICY_MATCH = UTIL_a_cmp(p, token_ptr, 32);
        }

        /* mechanism was supplied with a - indicating a failure on */
        if ((PREFIX_TYPE == SPF_H_FAIL) && (POLICY_MATCH == SPF_TRUE))
        {
          xpprintf("Found a match on a negative prefix.  Halting parse.\n");
          UTIL_assoc_prefix(p, SPF_H_FAIL, token_ptr);

          xfree(token);
          xfree(copy);

          return(SPF_FALSE);
        }

        break;
      } /* A */

       /*
       *  'mx' mechanism
      */
      case MX:
      {
        xprintf("policy mechanism is mx [%s]\n", token_ptr);

        /* we've been supplied an MX to use instead.. grab it */
        /* use tmp_ptr2 so we can use tmp_ptr again */
        if ((tmp_ptr = strstr(token_ptr, ":")) != NULL)
        {
          tmp_ptr++;
          tmp_ptr2 = tmp_ptr;
        }
        else
        {
          tmp_ptr2 = p->current_domain;
        }

        if ((tmp_ptr = strstr(token_ptr, "/")) != NULL)
        {
          tmp_ptr++;
          POLICY_MATCH = UTIL_mx_cmp(p, tmp_ptr2, atoi(tmp_ptr));
        }
        else
        {
          POLICY_MATCH = UTIL_mx_cmp(p, tmp_ptr2, 32);
        }

        /* mechanism was supplied with a - indicating a failure on */
        if ((PREFIX_TYPE == SPF_H_FAIL) && (POLICY_MATCH == SPF_TRUE))
        {
          xpprintf("Found a match on a negative prefix.  Halting parse.\n");

          UTIL_assoc_prefix(p, SPF_H_FAIL, token_ptr);

          xfree(token);
          xfree(copy);

          return(SPF_FALSE);
        }

        break;
      } /* MX */

       /*
       *  'ptr' mechanism
      */
      case PTR:
      {
        xprintf("policy mechanism is ptr [%s]\n", token_ptr);

        POLICY_MATCH = UTIL_ptr_cmp(p, token_ptr);

        /* mechanism was supplied with a - indicating a failure on */
        if ((PREFIX_TYPE == SPF_H_FAIL) && (POLICY_MATCH == SPF_TRUE))
        {
          xpprintf("Found a match on a negative prefix.  Halting parse.\n");

          break;
        }

        break;
      } /* PTR */

       /*
       *  'ip4' mechanism
      */
      case IP4:
      {
        xprintf("policy mechanism is ip4 [%s]\n", token_ptr);

        if ((policy_ip = UTIL_expand_ip(token_ptr)) == NULL)
        {
          xpprintf("ERROR: inet_pton unable to convert ip to binary\n");

          break;
        }

        xvprintf("POL: %lu [%s] PEER: %lu [%s]\n",
          policy_ip->addr.s_addr, token_ptr, p->addr.s_addr, p->r_ip);

        POLICY_MATCH = UTIL_cidr_cmp(policy_ip, &p->addr);
        xfree(policy_ip);

        /* mechanism was supplied with a - indicating a failure on */
        if ((PREFIX_TYPE == SPF_H_FAIL) && (POLICY_MATCH == SPF_TRUE))
        {
          xpprintf("Found a match on a negative prefix.  Halting parse.\n");
          UTIL_assoc_prefix(p, SPF_H_FAIL, token_ptr);

          xfree(token);
          xfree(copy);

          return(SPF_FALSE);
        }

        break;
      } /* IP4 */

       /*
       *  'ip6' mechanism
      */
      case IP6:
      {
        xprintf("policy mechanism is ip6 [%s]\n", token_ptr);

        break;
      } /* IP6 */

       /*
       *  'exists' mechanism
      */
      case EXISTS:
      {
        xprintf("policy mechanism is exists [%s]\n", token_ptr);

        if ((tmp_ptr = strstr(token_ptr, ":")) != NULL)
        {
          tmp_ptr++;

          if ((macro = MACRO_expand(p, tmp_ptr)) == NULL)
          {
            xvprintf("Unable to expand macro [%s]. Aborting.\n", tmp_ptr);

            break;
          }

          TMP_RES = p->RES;
          if ((dnsq_res = DNS_query(p, macro, T_A, NULL)) == NULL)
          {
            UTIL_assoc_prefix(p, TMP_RES, NULL); 
          }
          else if (dnsq_res == (char *)SPF_TRUE)
          {
            POLICY_MATCH = SPF_TRUE;
          }

          xfree(macro);
        }
        break;
      } /* EXISTS */

       /*
       *  'redirect' modifier
      */
      case REDIRECT:
      {
        xprintf("modifier is redirect [%s]\n", token_ptr);

        if ((tmp_ptr = strstr(token_ptr, "=")) != NULL)
        {
          tmp_ptr++;

          if (UTIL_is_macro(tmp_ptr) == SPF_TRUE)
          {
            if (p->redirect_buf == NULL)
            {
              if ((macro = MACRO_expand(p, tmp_ptr)) != NULL)
              {
                p->redirect_buf = xstrndup(macro, SPF_MAX_STR);
                xfree(macro);
              }
            }
            else
            {
              xvprintf("Got redir=%s, but redirect already set. Ignoring.\n",
                tmp_ptr);
            }
          }
          else
          {
            if (p->redirect_buf == NULL)
            {
              xvprintf("setting redirect_buf to %s\n", tmp_ptr);
              p->redirect_buf = xstrndup(tmp_ptr, SPF_MAX_STR);
            }
            else
            {
              xvprintf("Got redir=%s, but redirect already set. Ignoring.\n",
                tmp_ptr);
            }
          }
        }
        break;
      } /* REDIRECT */

       /*
       *  'explain' mechanism
      */
      case EXPLAIN:
      {
        xprintf("policy mechanism is explain [%s]\n", token_ptr);

        if ((tmp_ptr = strstr(token_ptr, "=")) != NULL)
        {
          tmp_ptr++;

          if ((macro = MACRO_expand(p, tmp_ptr)) == NULL)
          {
            xvprintf("Unable to expand macro [%s]. Aborting.\n", tmp_ptr);

            break;
          }

          p->explain = xstrndup(macro, (strlen(macro) + 1));
          xfree(macro);
        }
        else
        {
          xpprintf("EXPLAIN modifier must be accompanied " \
            "by arguments and I found none.");

          /* 'include' with no options returns unknown */
          POLICY_MATCH = SPF_TRUE;
          UTIL_assoc_prefix(p, SPF_UNKNOWN, token_ptr);

          xfree(token);
          xfree(copy);

          return(SPF_TRUE);
        }

        break;
      } /* EXPLAIN */

    } /* switch */

    xfree(token);
    cp += pos + 1;  /* move over to the next mechanism */

    if ((POLICY_MATCH == SPF_TRUE) && (p->spf_ver > 0))
    {
      UTIL_assoc_prefix(p, PREFIX_TYPE, p->last_m);
      p->RES_P = p->RES;

      xpprintf("returning SPF_TRUE\n");
      xfree(copy);

      return(SPF_TRUE);
    }
  } /* while parsing policy */

  xfree(copy);

  return(SPF_FALSE);
}


/* SPF_result
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   02/02/04
*
*  Desc:
*          Using the passed peer_info structure a string is generated which
*  can be used by the caller as a means of explaining the result of the SPF 
*  parse in human readable form (more or less).
*
*  Return:
*          A pointer to allocated memory containing the result string.  The
*  calling function is expected to free this memory.
*
*/
char *SPF_result(peer_info_t *p)
{
  char *buf = NULL;    /* return buffer */


  buf = xmalloc(SPF_MAX_HEADER);

  switch (p->RES)
  {
    case SPF_PASS:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_PASS, p->from, p->r_ip);

      break;
    } /* SPF_PASS */

    case SPF_NONE:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_NONE, p->from);

      break;
    } /* SPF_NONE */

    case SPF_S_FAIL:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_S_FAIL, p->from, p->r_ip);

      break;
    } /* SPF_S_FAIL */

    case SPF_H_FAIL:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_H_FAIL, p->from, p->r_ip);

      break;
    } /* SPF_H_FAIL */

    case SPF_ERROR:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_ERROR, p->from);

      break;
    } /* SPF_ERROR */

    case SPF_NEUTRAL:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_NEUTRAL, p->r_ip, p->from);

      break;
    } /* SPF_NEUTRAL */

    case SPF_UNKNOWN:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_UNKNOWN, p->from);

      break;
    } /* SPF_UNKNOWN */

    case SPF_UNMECH:
    {
      snprintf(buf, SPF_MAX_SMTP_RES, RES_UNMECH, p->from);

      break;
    } /* SPF_UNMECH */

  } /* switch */

  xprintf("response: [%s]\n", buf);

  return(buf);
}


/*  SPF_get_explain
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/25/04
*
*  Desc:
*          Takes the contents of a returned explain parse (if any),
*  allocates memory for it and returns that memory with the contents of
*  that string.
*
*  Return:
*          A pointer to allocated memory.  The caller is expected to free it.
*
*/
char *SPF_get_explain(peer_info_t *p)
{
  char *buf = NULL;    /* return buffer */


  if (p->explain != NULL)
  {
    if ((buf = MACRO_expand(p, SPF_EXPLAIN)) != NULL)
    {
      xprintf("Prepending explain: [%s]\n", buf);

      return(buf);
    }
  }

  return(NULL);
}


/*  SPF_build_header
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/25/04
*
*  Desc:
*          Generates and RFC2822 header as outlined by the SPF Draft RFC.
*  This header is in the form of 'X-Received-SPF: <string>' and is to be
*  prepended as early as possible in the SMTP process.  See the included
*  qmail, Sendmail or Courier patches for examples.
*
*  Return:
*          A pointer to allocated memory.  Calling function is expected to
*  free this.
*
*/
char *SPF_build_header(peer_info_t *p)
{
  char  *buf;    /* return buffer */

  buf = xmalloc(SPF_MAX_HEADER);

  switch (p->RES)
  {
    /* */
    case SPF_PASS:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_PASS].h, p->mta_hname,
        p->from, p->r_ip, p->mta_hname, p->r_ip, p->from);

      break;
    } /* SPF_PASS */

    /* */
    case SPF_NONE:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_NONE].h, p->mta_hname,
        p->from);

      break;
    } /* SPF_NONE */

    /* */
    case SPF_S_FAIL:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_S_FAIL].h, p->mta_hname,
        p->from, p->r_ip, p->mta_hname, p->r_ip, p->from);

      break;
    } /* SPF_S_FAIL */

    /* */
    case SPF_H_FAIL:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_H_FAIL].h, p->mta_hname,
        p->from, p->r_ip, p->mta_hname, p->r_ip, p->from);

      break;
    } /* SPF_H_FAIL */

    /* */
    case SPF_ERROR:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_ERROR].h, p->mta_hname,
        p->from);

      break;
    } /* SPF_ERROR */

    /* */
    case SPF_NEUTRAL:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_NEUTRAL].h, p->mta_hname,
        p->from, p->r_ip);

      break;
    } /* SPF_NEUTRAL */

    /* */
    case SPF_UNKNOWN:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_UNKNOWN].h, p->mta_hname,
        p->from, p->current_domain, p->last_m);

      break;
    } /* SPF_UNKNOWN */

    /* */
    case SPF_UNMECH:
    {
      snprintf(buf, SPF_MAX_HEADER, p->spf_result[SPF_UNMECH].h, p->last_m,
        p->mta_hname, p->from);

      break;
    } /*SPF_UNMECH */

  } /* switch */

  xvprintf("Prepending header string: [%s]\n", buf);

  return(buf);
}


/* SPF_smtp_helo
*
*  Author: Sean Comeau <scomeau@obscurity.org>
*          James Couzens <jcouzens@codeshare.ca>
*          Patrick Earl (http://patearl.net/)
*
*  Date:   12/10/03
*          12/25/03 (modified / renamed)
*          02/04/04 (modified)
*
*  Desc:
*          Fetches the HELO from MTA and places into the global peer_info
*  structure.  's' contains the string obtained from the connected client
*  by the calling MTA.
*
*  Return: 
*          SPF_TRUE if successful, SPF_FALSE if not.
*
*/
SPF_BOOL SPF_smtp_helo(peer_info_t *p, const char *s)
{
  if (s == NULL)
  {
    xepprintf("called with a NULL string (s)\n");

    return(SPF_FALSE);
  }

  xprintf("called with [%s]\n", s);

  if (p->helo)
  {
    xfree(p->helo);
  }

  p->helo = xstrdup(s);
  p->ehlo = p->helo;

  if (strlen(p->helo) > 0)
  {
    return(SPF_TRUE);
  }

  return (SPF_FALSE);
}


/* SPF_smtp_from
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*          Patrick Earl (http://patearl.net/)
*
*  Date:   12/10/03
*  Date:   12/25/03 James Couzens <jcouzens@codeshare.ca> (rewrite)
*  Date:   02/04/04 Patrick Earl (http://patearl.net) (modified)
*  Date:   02/05/04 Teddy <teddy@teddy.ch>
*  Date:   04/27/05 James Couzens <jcouzens@codeshare.ca> (fix '<' / '>' check)
*
*  Desc:
*          Called with a peer_info structure and 's' which is the data obtained
*  from the connecting client during an RFC2821 (pre-data) session,
*  specifically 's' is the arguments given after 'MAIL FROM: '  This data is
*  is then stored within the peer_info structure.
*
*  Please note that it is possible that this function might be called multiple
*  times during an SMTP transaction and so various variables from within the
*  passed peer_info_t structure are checked for a non-NULL status and are freed
*  if this is the case.
*
*  Return:
*          SPF_TRUE if successful, SPF_FALSE if not.
*
*/
SPF_BOOL SPF_smtp_from(peer_info_t *p, const char *s)
{
  int len = 0;               /* utility */

  const char *pos = NULL;    /* position in string */

  char *eos = NULL;          /* pointer to last char in string */


  /* 
  * Comment by: James Couzens <jcouzens@codeshare.ca>
  * Date:       04/17/05
  *
  *  xfree can be called to attempt to free memory even if its already freed
  *  but thats no excuse to be abusing it, its there to catch mistakes, not
  *  to ack as a lazy coder facilitation device
  *
  *  The reason freeing is being attempted is because it appears that people
  *  have been attempting to call this function multiple times within a single
  *  SPF parse, which logically would result in memory leakage because SPF_close
  *  isn't being called.
  *
  *  I honestly don't think its safe to be calling this function more than
  *  once but some users have reported success, I'll have to look into this...
 */

  if (p->from != NULL)
  {
    xfree(p->from);
  }

  if (p->spf_rlevel > 0)
  {
    xfree(p->current_domain);
  }

  if (p->original_domain != NULL)
  {
    xfree(p->original_domain);
  }


  p->RES = SPF_FALSE;

  /* if we didn't get a "MAIL-FROM:" string, try using their "HELO:" string */
  if (s == NULL)
  {
    /* no "HELO:", RFC says to use "unknown" */
    if ((p->helo != NULL) && (*(p->helo) == '\0'))
    {
      p->from = xstrndup("unknown", SIZEOF("unknown"));
    }
    else
    {
      p->from = xstrndup(p->helo, SPF_MAX_ENV_HELO);
    }

    xvprintf("NULL or invalid MAIL FROM rcvd.  Using %s from now on.\n",
      p->from ? p->from : p->helo);

    return(SPF_TRUE);
  }

  /*
   * Comment by: James Couzens <jcouzens@codeshare.ca>
   * Date:       April 27, 2005
   *
   * if the address starts with a '<' we need to strip it, and search for a 
   * closing '>', if there is no closing '>' we throw an error (for now)
   *
   * I've had to rewrite this portion because of the way it was written.
   * it was under certain circumsstances leaking 1 byte of memory, and this
   * is directly the result of the "uberleet h4x0r" way it was ambiguously
   * written. 
   *
  */
  pos = s;
  if ((eos = strstr(pos, ">")) != NULL)
  {
    if ((*pos == '<') && (*eos != '>')) 
    {
      xvprintf("Address [%s] started with '<' but did not end with '>'\n", s);

      return(SPF_FALSE);
    }
    else if (*pos == '<')
    {
      xpprintf("stripping '<' and '>'\n");

      pos++;    /* skip '<' */
      p->from = xstrndup(pos, strlen(pos));

      xprintf("p->from is: [%s]\n", p->from);
    }
  }
  else
  {
    p->from = xstrndup(s, SPF_MAX_STR);

    xprintf("p->from is: [%s]\n", p->from);
  }


  if (*p->from == '\0')
  {
    xprintf("Freeing p->from: [%s] because its first char is '\0'\n", p->from);
    xfree(p->from);

    if (*(p->helo) == '\0')
    {
      p->from = xstrndup("unknown", SIZEOF("unknown"));
    }
    else
    {
      p->from = xstrndup(p->helo, SPF_MAX_ENV_HELO);
    }
  }

  xprintf("MAIL-FROM: [%s]; called with: [%s]\n", p->from, s);

  /* look for a '@' within the address, if it doesn't exist, then its an 
   * invalid address and RFC821/2821 states that in this event we assign the
   * mail to be from user 'postmaster'@'p->current_domain'
  */
  if ((pos = strstr(p->from, "@")) != NULL)
  {
    /* length of local-part */
    len = (pos - p->from);

    if (len > SPF_MAX_LOCAL_PART)
    {
      xvprintf("truncating local-part because [%i] is > [%i] \n",
        len, SPF_MAX_LOCAL_PART);

      memcpy(p->local_part, p->from, SPF_MAX_LOCAL_PART);
      p->local_part[SPF_MAX_LOCAL_PART + 1] = '\0';
    }
    else
    {
      /* Copy everything up to the @ into local_part. */
      memcpy(p->local_part, p->from, len);
      p->local_part[len] = '\0';
    }

    pos++;    /* skip past the @ */
    p->original_domain = xstrndup(pos, SPF_MAX_STR);
   
    if (p->spf_rlevel > 0)
    {
      p->current_domain  = xstrndup(pos, SPF_MAX_STR);
    }
    else
    {
      p->current_domain = p->original_domain;
    }

    xprintf("Current domain: [%s]\n", p->current_domain);
    xprintf("Original domain: [%s]\n", p->original_domain);

  }
  else
  {
    snprintf(p->local_part, 11, "postmaster");
    p->original_domain = xstrndup(p->from, SPF_MAX_STR);

    if (p->spf_rlevel > 0)
    {
      p->current_domain = xstrndup(p->from, SPF_MAX_STR);
    }
    else
    {
      p->current_domain = p->original_domain;
    }
  }

  xvprintf("local-part: [%s]; domain: [%s]; sender: [%s]\n",
    p->local_part, p->current_domain, p->from);

  return(SPF_TRUE);
}


/* _SPF_clear_holdbufs
*
*  Author: Travis Anderson <tanderson@codeshare.ca>
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   09/11/04
*
*  Desc:
*          There are three possible 'holding' buffers that are used
*  only after an original parse comes back negative (ie anything other
*  that SPF_PASS), and this function simply goes through and free's
*  any memory they might have associated and assigns them a NULL
*  pointer.
*
*  This function is *PRIVATE* and you will never need to call it,
*  nor can it be referenced outside of this file, its purely
*  written for the benefit for SPF_parse_policy when dealing with
*  recursion for INCLUDE, REDIRECT, and CNAME.
*
*  Return:
*          SPF_TRUE upon success and SPF_FALSE upon failure.
*
*/
static SPF_BOOL _SPF_clear_holdbufs(peer_info_t *p)
{
  split_str_node_t *n = NULL;
  split_str_node_t *t = NULL;

  if (p == NULL)
  {
    xepprintf("peer_info_t structure was NULL!  Aborting!\n");

    return(SPF_FALSE);
  }

  if (p->cname_buf != NULL)
  {
    xfree(p->cname_buf);
    p->cname_buf = NULL;
  }

  if (p->redirect_buf != NULL)
  {
    xfree(p->redirect_buf);
    p->redirect_buf = NULL;
  }

  if (p->include_set != NULL)
  {
    n = p->include_set->head;
    while (n != NULL)
    {
      t = n->next;
      xfree(n->s);
      xfree(n);
      n = t;
    }

    xfree(p->include_set);
    p->include_set = NULL;
  }

  return(SPF_TRUE);
}

/* end main.c */
