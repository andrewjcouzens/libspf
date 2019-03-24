/* libspf - Sender Policy Framework library
*
*  ANSI C implementation of spf-draft-200405.txt
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Author: Sean Comeau <scomeau@obscurity.org>
*
*  File:   dns.c
*  Desc:   DNS related functions
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


#include "../../config.h"     /* autoconf */

#ifdef HAVE_PTHREAD_H
#include <pthread.h>          /* pthread_mutex_t */
#endif /* HAVE_PTHREAD_H */

#ifdef HAVE_GETHOSTBYNAME_R
#include <errno.h>            /* errno */
#endif /* HAVE_GETHOSTBYNAME_R */

#include "spf.h"              /* SPF */
#include "util.h"             /* Utility functions */
#include "dns.h"              /* our header */

#ifdef HAVE_PTHREAD_H 
  pthread_mutex_t dns_mutex = PTHREAD_MUTEX_INITIALIZER;    /* mutex */
#else
  void *dns_mutex;    /* mutex for gethostbyname dummy wrapper */
#endif /* HAVE_PTHREAD_H */

#ifdef HAVE_GETHOSTBYNAME_R
/* used by gethostbyname_r */
  extern int errno;
#endif /* HAVE_GETHOSTBYNAME_R */

/*! \file dns.c
*  \brief DNS Functions.
*
*  dns.c contains functions relating to the execution and processing of
*  DNS queries.  Each particular DNS record type has a unique function
*  that is designed to process such a response.
*/

/*! \fn char *DNS_query(peer_info_t *p, const char *s, const int T_TYPE,
const char *mta)
*  \param p      Global information structure containing client information
*  \param s      Domain name with which to perform the query against
*  \param T_TYPE Type of DNS record to lookup (eg: T_TXT, T_PTR, T_A, etc..)
*  \param mta    Used by DNS_ptr_answer in validation of an SPF ptr mechanism
*  \brief Execute a DNS query.
*
* Author: James Couzens <jcouzens@codeshare.ca>\n
* Author: Travis Anderson <tanderson@codeshare.ca>\n
*
* Date:   12/10/03\n
* Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>\n
*
* Desc:
*         Executes a DNS query of type T_TYPE and then calls the
* appropriate answer parsing function based on that type.  Returns
* a pointer to allocated memory (a string of space delimited
* records).  Upon failure returns NULL.
*
*/

/*! \fn char *DNS_txt_answer (int16_t ancount, const u_char *msg_ptr, const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
*  \param ancount Answer count
*  \param msg_ptr DNS message
*  \param eom_ptr Pointer to the end of the DNS message
*  \param rd_ptr  Pointer to a position in the DNS message
*  \param buf     Utiltiy buffer
*  \param ttl     Time To Live value of the DNS message
*  \brief Process a DNS message of type T_TXT
*
*  Author: James Couzens <jcouzens@codeshare.ca>\n
*
*  Date:   01/02/04\n
*  Date:   02/23/04 - Bugfix from Albert Weichselbraun <albert@atnet.at>\n
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>\n
*
*  Desc:
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in a TXT DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/

/*! \fn char *DNS_mx_answer(int16_t ancount, const u_char *msg_ptr, const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
*  \param ancount Answer count
*  \param msg_ptr DNS message
*  \param eom_ptr Pointer to the end of the DNS message
*  \param rd_ptr  Pointer to a position in the DNS message
*  \param buf     Utiltiy buffer
*  \param ttl     Time To Live value of the DNS message
*  \brief Process a DNS message of type T_MX
*
*  Author: James Couzens <jcouzens@codeshare.ca>\n
*
*  Date:   01/02/04\n
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>\n
*
*  Desc:
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in an MX DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/

/*! \fn SPF_BOOL DNS_ptr_answer(peer_info_t *p, int16_t ancount, const u_char *msg_ptr, const u_char *eom_ptr, u_char *rd_ptr, char *buf, const char *mta, int *ttl)
*  \param p       Global information structure containing client information
*  \param ancount Answer count
*  \param msg_ptr DNS message
*  \param eom_ptr Pointer to the end of the DNS message
*  \param rd_ptr  Pointer to a position in the DNS message
*  \param buf     Utiltiy buffer
*  \param mta     IP address of the authoritative MX
*  \param ttl     Time To Live value of the DNS message
*  \brief Process a DNS message of type T_PTR
*
*  Author: James Couzens <jcouzens@codeshare.ca>\n
*
*  Date:   01/02/04\n
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>\n
*
*  Desc:
*          A reverse lookup on an IP address leads to a lookup per returned
*  PTR answer to see if the returned answer matches.  The forward lookups are
*  handled by a separate function which calls gethostbyname.  Upon a single
*  successful match of a forward lookup with a reverse lookup, returns SPF_TRUE.
*  Returns SPF_FALSE upon failure.
*
*/

/*! \fn char *DNS_cname_answer(int16_t ancount, const u_char *msg_ptr, const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
*  \param ancount Answer count
*  \param msg_ptr DNS message
*  \param eom_ptr Pointer to the end of the DNS message
*  \param rd_ptr  Pointer to a position in the DNS message
*  \param buf     Utiltiy buffer
*  \param ttl     Time To Live value of the DNS message
*  \brief Process a DNS message of type T_MX
*
*  Author: Teddy <teddy@teddy.ch>\n
*
*  Date:   29/04/04\n
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>\n
*
*  Desc:\n
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in a TXT DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/

/* DNS_query
*
* Author: James Couzens <jcouzens@codeshare.ca>\n
* Author: Travis Anderson <tanderson@codeshare.ca>\n
*
* Date:   12/10/03
* Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>
*
* Desc:
*         Executes a DNS query of type T_TYPE and then calls the
* appropriate answer parsing function based on that type.  Returns
* a pointer to allocated memory (a string of space delimited
* records).  Upon failure returns NULL.
*
*/
char *DNS_query(peer_info_t *p, const char *s, const int T_TYPE,
  const char *mta)
{
  HEADER *hdr = NULL;        /* pointer to the header of the packet */

  int8_t ancount = 0;        /* number of answers */

  int16_t r_len  = 0;        /* res_search return code & packet len */
  int16_t rc     = 0;        /* generic return code / length of */

  int ttl = 0;               /* answer TTL */

  u_char *answer  = NULL;    /* query response (answer) buffer */

  char *buf     = NULL;      /* record extraction buffer */
  char *rr_data = NULL;      /* record */

  u_char *msg_ptr = NULL;    /* pointer to beginning of the message */
  u_char *eom_ptr = NULL;    /* pointer to the end of the message */
  u_char *rd_ptr  = NULL;    /* pointer to uncompressed message */


  if (s == NULL)
  {
    xepprintf("Passed a NULL char.  Aborting.\n");

    return(NULL);
  }

  xprintf("Called with [%s] and type: %i\n", s, T_TYPE);

  answer = xmalloc(SPF_PACKETSZ);

   /* 
   * Comment by: James Couzens <jcouzens@codeshare.ca>
   * Date:       03/03/05
   *
   * Using 'res_search' results in undesirable behaviour breaking the language
   * of RFC821 and RFC2821 as is pointed out by Marc Lehmann <pcg@goof.com> in
   * this thread: http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=297060 of 
   * the DEBIAN bug tracker list.  The long and the short of it is that if you
   * were not already aware using res_search implements the 'default' and
   * 'search' rules controlled by RES_DEFNAMES and RES_DNSRCH.  See man page of
   * 'res_search' for more information.
   *
   * The resulting change is 'res_query' is now used by default, however I have
   * left 'res_search' available through the AutoConf flag 
   * '--enable-res-search' for those are using this functionality to facilitate
   * local override policies outside of the functionality written into this 
   * library and suggested by the SPF RFC.
   *
  */

#ifdef _WITH_RES_SEARCH
  r_len  = res_search(s, C_IN, T_TYPE, answer, SPF_PACKETSZ);
#else
  r_len  = res_query(s, C_IN, T_TYPE, answer, SPF_PACKETSZ);
#endif /* _WITH_RES_SEARCH */

  if (r_len <= 0)
  {
    switch (h_errno)
    {
      case HOST_NOT_FOUND:
      {
        snprintf(p->error, SPF_MAX_ERROR, "%s\n", hstrerror(h_errno));
        UTIL_assoc_prefix(p, SPF_NONE, NULL);
        xvprintf("%s\n", p->error);

        xfree(answer);

        return(NULL);
      }
      case TRY_AGAIN:
      {
        snprintf(p->error, SPF_MAX_ERROR, "%s\n", hstrerror(h_errno));
        UTIL_assoc_prefix(p, SPF_NONE, NULL);
        xvprintf("%s\n", p->error);

        xfree(answer);

        return(NULL);
      }
      case NO_RECOVERY:
      {
        snprintf(p->error, SPF_MAX_ERROR, "%s\n", hstrerror(h_errno));
        UTIL_assoc_prefix(p, SPF_ERROR, NULL);
        xvprintf("%s\n", p->error);

        xfree(answer);

        return(NULL);
      }
      case NO_DATA:
      {
        snprintf(p->error, SPF_MAX_ERROR, "%s\n", hstrerror(h_errno));
        UTIL_assoc_prefix(p, SPF_NONE, NULL);
        xvprintf("%s\n", p->error);

        xfree(answer);

        return(NULL);
      }
      default:
      {
        snprintf(p->error, SPF_MAX_ERROR, "%s\n", hstrerror(h_errno));
        UTIL_assoc_prefix(p, SPF_ERROR, NULL);
        xvprintf("%s\n", p->error);

        xfree(answer);

        return(NULL);
      } 
    } /* switch */
  } /* if */

  hdr = (HEADER *)answer;

  if ((ancount = ntohs(hdr->ancount)) <= 0)
  {
    xfree(answer);
    
    xpprintf("returning NULL because there was no ANSWER\n");
    
    return(NULL);
  }

  xvprintf("Received packet size of %i bytes which contains %i answers.\n",
    r_len, ancount);

  xvprintf("ANSWERS: %i\n", ancount);
  xvprintf("QUESTIONS: %i\n", ntohs(hdr->qdcount));

  msg_ptr = answer;                 /* point to start of message */
  eom_ptr = (answer + r_len);       /* point to end of message */
  rd_ptr  = (answer + HFIXEDSZ);    /* point to start of RDATA */

  if ((rc = dn_skipname(rd_ptr, eom_ptr)) < 0)
  {
    xepprintf("Error obtaining QUESTION!\n");

    xfree(answer);

    return(NULL);
  }

  rd_ptr += (rc + QFIXEDSZ);      /* jump to start of ANSWER */

  buf = xmalloc(SPF_MAXDNAME);

  switch (T_TYPE)
  {
     /*
     * T_A: A 'a' or address record used to associate an IP address with any
     *      given hostname.
    */
    case T_A:
    {
      xfree(buf);
      xfree(answer);

      return((char *)SPF_TRUE);
     }

     /*
     * T_TXT: A 'txt' or TEXT record which is what is currently used to store
     * the SPF records within DNS.  Its unfortunate that this had to be done
     * because you'll discover that I had to make concessions to deal with
     * the fact that many people publish more than just SPF records using
     * the T_TXT record type, especially considering it was seeing use long
     * before SPF ever came on the scene.  Hopefully this will change in the
     * near future.
    */
    case T_SPF:
    case T_TXT:
    {
      if ((rr_data = DNS_txt_answer(ancount, (u_char *)msg_ptr, (u_char *)eom_ptr,
        (u_char *)rd_ptr, buf, &ttl)) == NULL)
      {
        xfree(buf);
        xfree(answer);

        return(NULL);
      }

      break;
    }

    /*
     * T_MX: A 'mx' or Mail Exchanger (Server) record identifies an authorative
     *       mail server (or in multiples server(s)) which may be used to deliver
     *       e-mail to a given domain.
    */
    case T_MX:
    {
      if ((rr_data = DNS_mx_answer(ancount, (u_char *)msg_ptr, (u_char *)eom_ptr,
        (u_char *)rd_ptr, buf, &ttl)) == NULL)
      {
        xfree(buf);
        xfree(answer);

        return(NULL);
      }

      break;
    }

    /*
    * T_PTR: A 'ptr' DNS record contains the reverse address for a
    *        given hostname in the format x.x.x.x-in-addr.arpa in the
    *        case of IPv4.
   */
    case T_PTR:
    {

       /*
       * Comment by: James Couzens <jcouzens@codeshare.ca>
       * Date:       01/04/04
       *
       * DNS_ptr_answer doesn't allocate any memory and returns SPF_TRUE or
       * SPF_FALSE, however this function returns a char so a the boolean 
       * value of SPF_TRUE/FALSE is cast to avoid writing a handler for 
       * this one specific instance.  I might change this in the future by
       * either altering its return type or something else but for now this
       * seems to do nicely.
      */
      if (DNS_ptr_answer(p, ancount, (u_char *)msg_ptr, (u_char *)eom_ptr,
        (u_char *)rd_ptr, buf, mta, &ttl) == SPF_FALSE)
      {
        xfree(buf);
        xfree(answer);

        return((char *)SPF_FALSE);
      }
      else
      {
        xfree(buf);
        xfree(answer);

        return((char *)SPF_TRUE);
      }

      break;
    }

     /*
     * T_CNAME: A 'cname' or an alias record for a DNS forward or reverse
     *          record which has been assigned more than one value.
    */
    case T_CNAME:
    {
      if ((rr_data = DNS_cname_answer(ancount, (u_char *)msg_ptr, (u_char *)eom_ptr,
        (u_char *)rd_ptr, buf, &ttl)) == NULL)
      {
        xfree(answer);
        xfree(buf);

        return(NULL);
      }
      break;
    }

    default:
    {
      break;
    }
  } /* switch */

  xfree(buf);
  xfree(answer);

  snprintf(p->txt, SPF_MAX_STR, "%s", rr_data);
 
  xvprintf("returning rr_data: [%s]\n", rr_data);

  return(rr_data);
}


/* DNS_txt_answer
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/02/04
*  Date:   02/23/04 - Bugfix from Albert Weichselbraun <albert@atnet.at>
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>
*
*  Desc:
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in a TXT DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/
char *DNS_txt_answer(int16_t ancount, const u_char *msg_ptr,
  const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
{

  int16_t i         = 0;    /* utility */
  int16_t j         = 0;    /* utility */
  int16_t rc        = 0;    /* generic return code / length of */
  int16_t rd_type   = 0;    /* answer type */
  int16_t rd_len    = 0;    /* res_search return code & packet len */

  int32_t rd_ttl    = 0;    /* TTL */

  size_t substr_len = 0;    /* sub string length, for use with DNS records
                             * which break strings apart using quotation 
                             * marks ie: "v=spf1 " "a:10.0.0.0/24 " etc.. 
                             * this counter is used during the assembly    
                             * of such a record */

  char *rr_data = NULL;     /* data pointer */


  if ((msg_ptr == NULL) ||
      (eom_ptr == NULL) ||
      (rd_ptr  == NULL) ||
      (buf     == NULL))
  {
    xepprintf("Called with NULL pointers\n");

    return(NULL);
  }

  xpprintf("entering function\n");

  i = 0;
  j = ancount;
  while ((ancount > 0) && (rd_ptr < eom_ptr))
  {
    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Unable to expand T_TXT response packet!; Reason: %s\n",
        hstrerror(h_errno));

      if (rr_data != NULL)
      {
        xfree(rr_data);
      }

      return(NULL);
    }

    /* dname, type, class, TTL, rdata len, rdata */
    rd_ptr += rc;                 /* jump to start of ANSWER data */
    GETSHORT(rd_type, rd_ptr);    /* get response type */
    rd_ptr += INT16SZ;            /* skip class */
    GETLONG(rd_ttl, rd_ptr);      /* get TTL */
    GETSHORT(rd_len, rd_ptr);     /* get data length */

    *ttl = rd_ttl;                /* TTL working pointer */

    if ((rd_type != T_TXT) && (rd_type != T_SPF))
    {
      xvprintf("Ignoring record not of T_TXT type. [%i]\n", rd_type);
      rd_ptr += rd_len;

      continue;
    }

    xvprintf("Found T_TXT record: [%s]; length: [%i]\n", rd_ptr, rd_len);

    /*
     * Only received one answer, so this MUST start with v=spf1 or its
     * not a valid SPFv1 record otherwise validate the string for its contents
     * to contain a valid SPF mechanism otherwise, skip it.
    */
    if ((j == 1) && (strstr(rd_ptr, "v=spf1") == NULL))
    {
      xvprintf("INVALID Answer Data: [%s] len: %i\n", rd_ptr, rd_len);

      if (rr_data != NULL)
      {
        xfree(rr_data);
      }

      return(NULL);
    }
    else if (strstr(rd_ptr, "v=spf1") == NULL)
    {
      xvprintf("Contents of SPF record not relevant: [%s]\n", rd_ptr);

      rd_ptr += rd_len;

      continue;
    }

    /* 
    * If we're here we should have a string that at the very least contains
    * some valid SPF related material, however because the RFC states that
    * in order to facilitate both length SPF records, and additionally
    * a namserver that might split up length SPF records, we need to
    * concatenate these multiple responses into one string.i
   */
    while (rd_len > 0)
    {
      substr_len = *rd_ptr;
      rd_ptr += 1;
      rd_len -= 1;

      xvprintf("substr_len: [%i]\n", substr_len);
      xvprintf("rd_ptr: [%s]\n", rd_ptr);
      xvprintf("rd_len: [%i]\n", rd_len);

      if (rr_data == NULL)
      {
        rr_data = xmalloc(substr_len + 2);
      }
      else
      {
        rr_data = xrealloc(rr_data, (i + substr_len + 2));
      }

      strncat(rr_data, (char *)rd_ptr, substr_len);

      rd_ptr += substr_len;    /* move forward length of substr */
      rd_len -= substr_len;    /* subtract length of substr from overall len */
      i      += substr_len;    /* increment utility var length of substr */
    }

    /* tack a space on the end because we're expecting more... */
    rr_data[i] = ' ';
    i += 1;
    rr_data[i] = '\0';
 
    xvprintf("Answer %i [%s] has length %i. [%i]\n",
      ancount, rr_data, rd_len, i);

    xvprintf("Answer Data: [%s] len: [%i]\n", rd_ptr, rd_len);
  }

  if (rr_data != NULL)
  {
    xprintf("Returning DNS response: [%s]\n", rr_data);

    return(rr_data);
  }

  xpprintf("rr_data is NULL, returning as such\n");
  
  return(NULL);
  
}


/* DNS_mx_answer
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/02/04
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>
*
*  Desc:
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in an MX DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/
char *DNS_mx_answer(int16_t ancount, const u_char *msg_ptr,
  const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
{
  size_t buf_len = 0;      /* buffer length */

  int16_t i       = 0;     /* utility */
  int16_t rc      = 0;     /* generic return code / length of */
  int16_t rd_pref = 0;     /* MX preference */
  int16_t rd_type = 0;     /* answer type */
  int16_t rd_len  = 0;     /* res_search return code & packet len */

  int32_t rd_ttl = 0;      /* TTL */

  char *rr_data = NULL;    /* data pointer */


  i = 0;
  while ((ancount > 0) && (rd_ptr < eom_ptr))
  {
    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      return(NULL);
    }

    /* dname, type, class, TTL, rdata len, rdata */
    rd_ptr += rc;                 /* jump to start of ANSWER data */
    GETSHORT(rd_type, rd_ptr);    /* get response type */
    rd_ptr += INT16SZ;            /* skip class */
    GETLONG(rd_ttl, rd_ptr);      /* get TTL */
    GETSHORT(rd_len, rd_ptr);     /* get data length */

    *ttl = rd_ttl;

    if (rd_type != T_MX)
    {
      xprintf("Forged packet?!  We requested T_MX (15) but got %i\n", rd_type);
      rd_ptr += rd_len;
      continue;
    }

    GETSHORT(rd_pref, rd_ptr);  /* get MX preference */

    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      return(NULL);
    }

    xvprintf("MX: %s Preference: %i\n", buf, rd_pref);

    buf_len = strlen(buf);
    i += (buf_len + 1);

    if ((rd_len <= SPF_MAXDNAME) && (rd_len > 0))
    {
      if (rr_data == NULL)
      {
        rr_data = xmalloc(i + 1);
      }
      else
      {
        rr_data = xrealloc(rr_data, (i + 1));
      }

      xvprintf("REALLOCATE memory: %i bytes\n", (i + 1));

      strncat(rr_data, buf, buf_len);
      rr_data[i - 1] = ' ';
      rr_data[i] = '\0';
    }

    rd_ptr += rc;
    ancount--;
  }

  if (rr_data != NULL)
  {
    rr_data[i - 1] = '\0';
  }

  return(rr_data);
}


/* DNS_ptr_answer
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*
*  Date:   01/02/04
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>
*
*  Desc:
*          A reverse lookup on an IP address leads to a lookup per returned
*  PTR answer to see if the returned answer matches.  The forward lookups are
*  handled by a separate function which calls gethostbyname.  Upon a single
*  successful match of a forward lookup with a reverse lookup, returns SPF_TRUE.
*  Returns SPF_FALSE upon failure.
*
*/
SPF_BOOL DNS_ptr_answer(peer_info_t *p, int16_t ancount,
const u_char *msg_ptr, const u_char *eom_ptr, u_char *rd_ptr, char *buf,
  const char *mta, int *ttl)
{
  int16_t rc      = 0;      /* generic return code / length of */
  int16_t rd_type = 0;      /* answer type */
  int16_t rd_len  = 0;      /* res_search return code & packet len */

  int32_t rd_ttl = 0;       /* TTL */

  char *buf_cmp  = NULL;    /* stores domain from buf's (ptr res) hostname */
  char *mta_cmp  = NULL;    /* stores domain from rpeer's hostname */


  while ((ancount > 0) && (rd_ptr < eom_ptr))
  {
    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      return(SPF_FALSE);
    }

    /* dname, type, class, TTL, rdata len, rdata */
    rd_ptr += rc;                 /* jump to start of ANSWER data */
    GETSHORT(rd_type, rd_ptr);    /* get response type */
    rd_ptr += INT16SZ;            /* skip class */
    GETLONG(rd_ttl, rd_ptr);      /* get TTL */
    GETSHORT(rd_len, rd_ptr);     /* get data length */

    *ttl = rd_ttl;

    if (rd_type != T_PTR)
    {
      rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME);

      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      xvprintf("Got answer to type %i [%s] when we asked for T_PTR [%i]\n",
        rd_type, buf, T_PTR);

      rd_ptr += rd_len;

      continue;
    }

    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      xvprintf("Error expanding ANSWER packet at count %i. [%s]\n",
        ancount, buf);

      return(SPF_FALSE);
    }

    xvprintf("Answer %i has length %i.\n", ancount, rd_len);
    xvprintf("Answer data (buffer): [%s]; buffer length: %i\n",
      buf, strlen(buf));

    sleep(1);

    if ((rd_len <= SPF_MAXDNAME) && (rd_len > 0))
    {
      if (UTIL_validate_hostname(p, buf, 32) == SPF_FALSE)
      {
        xvprintf("Unable to validate hostname [%s] with [%s]\n",
          buf, mta);

        rd_ptr += rc;
        ancount--;

        continue;
      }

      /* buf MUST be a subdomain of mta */
      if (strlen(buf) < strlen(mta))
      {
        /* not a chance */
        rd_ptr += rc;
        ancount--;

        continue;
      }
      else if (strlen(buf) == strlen(mta))
      {
        if (strcasecmp(buf, mta) == 0)
        {
          return (SPF_TRUE);
        }
        else
        {
          rd_ptr += rc;
          ancount--;

          continue;
        }
      }
      else
      {
        /* place these two pointers at the end of each string */
        buf_cmp = &(buf[strlen(buf) - 1]);
        mta_cmp = (char *)&(mta[strlen(mta) - 1]);

        /* walk backwards through both strings looking for a match */
        while (mta_cmp != (mta - 1))
        {
          xvprintf("mta_cmp: [%s]\n", mta_cmp);
          xvprintf("buf_cmp: [%s]\n", buf_cmp);

          if (*mta_cmp-- != *buf_cmp--)
          {
            rd_ptr += rc;
            ancount--;

            continue;
          }
        }

        if (*buf_cmp == '.')
        {
          return (SPF_TRUE);
        }
        else
        {
          rd_ptr += rc;
          ancount--;

          continue;
        }
      }
    }
    else
    {
      xepprintf("Answer length is too long!\n");
    }

    rd_ptr += rc;
    ancount--;
  }

  return(SPF_FALSE);
}


/* DNS_cname_answer
*
*  Author: Teddy <teddy@teddy.ch>
*
*  Date:   29/04/04
*  Date:   02/20/04 - Added cache by Travis Anderson <tanderson@codeshare.ca>
*
*  Desc:
*          SPF_PACKETSZ bytes are allocated and then filled with \0 chars.
*  This buffer is then used in a TXT DNS query using data from the passed
*  peer_info_t structure.  Upon success this buffer is re-cast as a char *
*  and then a pointer to this memory is returned.  Upon failure a NULL
*  pointer is returned.
*
*/
char *DNS_cname_answer(int16_t ancount, const u_char *msg_ptr,
  const u_char *eom_ptr, u_char *rd_ptr, char *buf, int *ttl)
{
  int16_t i       = 0;     /* utility */
  int16_t rc      = 0;     /* generic return code / length of */
  int16_t rd_type = 0;     /* answer type */
  int16_t rd_len  = 0;     /* res_search return code & packet len */

  int32_t rd_ttl = 0;      /* TTL */

  size_t buf_len = 0;      /* buffer length */

  char *rr_data = NULL;    /* data pointer */


  if ((msg_ptr == NULL) || (eom_ptr == NULL) ||
      (rd_ptr == NULL)  || (buf == NULL))
  {
    xepprintf("Called with NULL pointers\n");

    return(NULL);
  }

  xpprintf("entering function\n");

  i = 0;
  while ((ancount > 0) && (rd_ptr < eom_ptr))
  {
    if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      return(NULL);
    }

    /* dname, type, class, TTL, rdata len, rdata */
    rd_ptr += rc;                 /* jump to start of ANSWER data */
    GETSHORT(rd_type, rd_ptr);    /* get response type */
    rd_ptr += INT16SZ;            /* skip class */
    GETLONG(rd_ttl, rd_ptr);      /* get TTL */
    GETSHORT(rd_len, rd_ptr);     /* get data length */

    *ttl = rd_ttl;

    if (rd_type != T_CNAME)
    {
      xvprintf("Ignoring record not of T_CNAME type. [%i]\n", rd_type);
      rd_ptr += rd_len;

      continue;
    }

    if (dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME) < 0)
    {
      xvprintf("Error expanding ANSWER packet at count %i; Reason: %s \n",
        ancount, hstrerror(h_errno));

      return(NULL);
    }

    buf_len = strlen(buf);
    i += (buf_len + 1);

    if ((rd_len <= SPF_MAXDNAME) && (rd_len > 0))
    {
      if (rr_data == NULL)
      {
        rr_data = xmalloc(i + 1);
      }
      else
      {
        rr_data = xrealloc(rr_data, (i + 1));
      }

      xvprintf("REALLOCATE memory: %i bytes\n", (i + 1));

      strncat(rr_data, buf, buf_len);
      rr_data[i - 1] = ' ';
      rr_data[i] = '\0';
    }

    rd_ptr += rc;
    ancount--;
  }

  if (rr_data != NULL)
  {
    rr_data[i - 1] = '\0';
  }

  xvprintf("returning [%s]\n", rr_data);
  return(rr_data);
}


/* DNS_check_client_reverse
*
*  Author: Travis Anderson <tanderson@codeshare.ca>
*          Adapted from DNS_query
*
*  Date:   08/??/04 
*
*  Desc:
*          First get addr's reverse then for each hostname returned, 
*  resolve it and then see if it matches addr.  If a match is found return 
*  SPF_TRUE if not return SPF_FALSE.
*
*/
SPF_BOOL DNS_check_client_reverse(peer_info_t *p)
{

  HEADER  *hdr = NULL;       /* pointer to the header of the packet */

  int8_t ancount = 0;        /* number of answers */

  int16_t rd_type = 0;       /* answer type */
  int16_t rd_len  = 0;       /* res_search return code & packet len */
  int16_t r_len   = 0;       /* res_search return code & packet len */
  int16_t rc      = 0;       /* generic return code / length of */

  char *buf    = NULL;       /* record extraction buffer */
  char *answer = NULL;       /* query response (answer) buffer */

  char *addr_arpa = NULL;    /* reverse address in dot-quad notation */

  u_char *msg_ptr = NULL;    /* pointer to beginning of the message */
  u_char *eom_ptr = NULL;    /* pointer to the end of the message */
  u_char *rd_ptr  = NULL;    /* pointer to uncompressed message */


  if (p == NULL)
  {
    xepprintf("Unable to continue, peer info struct is NULL!\n");

    return(SPF_FALSE);
  }

  xpprintf("entering function\n");

  addr_arpa = UTIL_rev_addr(p->r_ip);
  
  answer = xmalloc(SPF_PACKETSZ);

#ifdef _WITH_RES_SEARCH
  r_len = res_search(addr_arpa, C_IN, T_PTR, (u_char *)answer, SPF_PACKETSZ);
#else
  r_len = res_query(addr_arpa, C_IN, T_PTR, (u_char *)answer, SPF_PACKETSZ);
#endif /* _WITH_RES_SEARCH */

  xfree(addr_arpa);

  hdr     = (HEADER *)answer;
  ancount = ntohs(hdr->ancount);

  xvprintf("Received packet size of %i bytes which contains %i answers.\n",
    r_len, ancount);

  xvprintf("ANSWERS: %i\n",   ancount);
  xvprintf("QUESTIONS: %i\n", ntohs(hdr->qdcount));

  if (ancount > 0)
  {
    msg_ptr = (u_char *)answer;                 /* point to start of message */
    eom_ptr = ((u_char *)answer + r_len);       /* point to end of message */
    rd_ptr  = ((u_char *)answer + HFIXEDSZ);    /* point to start of RDATA */

    if ((rc = dn_skipname(rd_ptr, eom_ptr)) < 0)
    {
      xepprintf("Error obtaining QUESTION!\n");
      xfree(answer);

      return(SPF_FALSE);
    }

    rd_ptr += rc + QFIXEDSZ;    /* jump to start of ANSWER */

    buf = xmalloc(SPF_MAXDNAME);

    while ((ancount > 0) && (rd_ptr < eom_ptr))
    {
      if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
      {
        xeprintf("Error expanding ANSWER packet at count %i. [%s]\n",
          ancount, buf);
       
        xfree(answer);
        xfree(buf);

        return(SPF_FALSE);
      }

       /* dname, type, class, TTL, rdata len, rdata */
      rd_ptr += rc;                 /* jump to start of ANSWER data */
      GETSHORT(rd_type, rd_ptr);    /* get response type */
      rd_ptr += INT16SZ;            /* skip class */
      rd_ptr += INT32SZ;            /* skip TTL */
      GETSHORT(rd_len, rd_ptr);     /* get data length */

      if (rd_type != T_PTR)
      {
        rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME);

        xvprintf("Got answer to type %i [%s] when we asked for T_PTR [%i]\n",
          rd_type, buf, T_PTR);

        rd_ptr += rd_len;

        continue;
      }

      if ((rc = dn_expand(msg_ptr, eom_ptr, rd_ptr, buf, SPF_MAXCDNAME)) < 0)
      {
        xvprintf("Error expanding ANSWER packet at count %i. [%s]\n",
          ancount, buf);

        xfree(answer);
        xfree(buf);

        return(SPF_FALSE);
      }

      xvprintf("Answer %i has length %i.\n", ancount, rd_len);
      xvprintf("Answer data (buffer): [%s]; data length: %i\n",
        buf, strlen(buf));

      if ((rd_len <= SPF_MAXDNAME) && (rd_len > 0))
      {
        if (UTIL_validate_hostname(p, buf, 32) == SPF_FALSE)
        {
          xvprintf("Unable to validate hostname [%s] with [%s]\n",
            buf, p->r_ip);

          rd_ptr += rc;
          ancount--;

          continue;
        }
        else
        {
          if (p->r_vhname != NULL)
          {
            xfree(p->r_vhname);
          }

          p->r_vhname = xstrndup(buf, strlen(buf) + 1);

          xfree(answer);
          xfree(buf);

          return(SPF_TRUE);
        } /* if (UTIL_validate.. */
      }
      else
      {
        xepprintf("Answer length is too long!\n");
        continue; 
      }

      rd_ptr += rc;
      ancount--;

    } /* if (rd_len */
  } /* while (ancount */

  xfree(answer);
  xfree(buf);

  return(SPF_FALSE);
}

#ifdef HAVE_GETHOSTBYNAME_R

/* _DNS_gethostbyname_r
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Date:   08/28/04
*
*  Desc:
*          A wrapper around the GNU gethostbyname_r extension function which
*  introduces reentrant (some) resolver functionality allbeit way too bloody
*  late.  Someone smack me with a tire iron and rewrite all of this using DJB.
*
*  This function is intented to be wrapped by a MACRO going by something along
*  the lines of 'xgethostbyname' or 'xgethostbyname_r'.
*
*/
struct hostent *_DNS_GNU_gethostbyname_r(const char *name,
  struct hostent *result, char *buf, int buf_len, int *h_errnop)
{
  struct hostent hp = {0};

  struct hostent *ret_hp = NULL;

 
  if (!name)
  {
    xepprintf("ERROR: No hostname to resolve.\n");

    return(NULL);
  }

  xpprintf("entering function\n");

  if (buf_len >= SPF_MAX_STR)
  {
    xvprintf("buf_len [%i] is > max size [%i]; Disregarded.\n",
      buf_len, SPF_MAX_STR);
 
    return(NULL);
  }
 
  ret_hp = &hp;
 
  xvprintf("called with hostname [%s]\n", name);
  memset(buf, '\0', SPF_MAX_GHBNR_DBUF);
  /*hp = xmalloc(SIZEOF(struct hostent));*/

  if (gethostbyname_r(name, result, buf, (size_t)buf_len, &ret_hp, h_errnop) != 0)
  {
    xepprintf("gethostbyname_r call failed\n");

    return(NULL);
  }

  xpprintf("leaving function\n");

  return(ret_hp);
}

#else /* HAVE_GETHOSTBYNAME_R */

/* _DNS_gethostbyname_r
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Date:   08/28/04
*
*  Desc:
*          Reentrant version of gethostbyname_r which is available as a
*  GNU extension but unavailable to everyone else, so I've opted to
*  implement it here.  This function is intented to be wrapped by a
*  MACRO going by something along the lines of 'xgethostbyname' or
*  'xgethostbyname_r'
*
*  Calling function is responsible to call _DNS_gethostbyname_r_free
*  to unlock the mutex.
*
*/
struct hostent *_DNS_gethostbyname_r(const char *name,
  struct hostent *result, char *buf, int buf_len, int *h_errnop)
{
  struct hostent *hp = NULL;    /* hostent structure */


  if (!name)
  {
    xepprintf("ERROR: No hostname to resolve!\n");
    
    return(NULL);
  }

  xvprintf("called with hostname [%s]\n", name);

  xpthread_mutex_lock(&dns_mutex);

  hp = gethostbyname(name);
  *h_errnop = h_errno;

  xpprintf("leaving function\n");

  return(hp);
}

#endif /* HAVE_GETHOSTBYNAME_R */


/* _DNS_gethostbyname_r_free
*
*  Author: James Couzens <jcouzens@codeshare.ca>
*  Date:   08/28/04
*
*  Desc:
*          This function unlocks the mutex which was locked when
*  _DNS_gethostbyname_r was called as a reentrant wrapper around the
*  non-threadsafe 'gethostbyname' function call.  This function is
*  intended to be wrapped by a MACRO going by something along the lines
*  of 'xgethostbyname_free' or 'xgethostbyname_r_free'
*
*
*/
void _DNS_gethostbyname_r_free(void)
{
#ifdef _WITH_PTHREADS
  xpthread_mutex_unlock(&dns_mutex);
#endif /* _WITH_PTHREADS */

  return;
}



/* end dns.c */
