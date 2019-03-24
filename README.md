
           oooo   o8o   .o8        .oooooo..o ooooooooo.   oooooooooooo
           `888   `"'  "888       d8P'    `Y8 `888   `Y88. `888'     `8
            888  oooo   888oooo.  Y88bo.       888   .d88'  888
            888  `888   d88' `88b  `"Y8888o.   888ooo88P'   888oooo8
            888   888   888   888      `"Y88b  888          888    "
            888   888   888   888 oo     .d8P  888          888
           o888o o888o  `Y8bod8P' 8""88888P'  o888o        o888o

--------------------------------------------------------------------------------
            An ANSI C Implementation of the Sender Policy Framework
--------------------------------------------------------------------------------


  Table of Contents
  -----------------

  1.0 ............. Installation
  2.0 ............. Patches
  3.0 ............. Examples
  4.0 ............. Documentation
   4.1 ............ MTA specific
   4.2 ............ API specific
   4.3 ............ Resources
  5.0 ............. Source Code
  6.0 ............. License
  7.0 ............. Portability
  8.0 ............. Resources
   8.1 ............ Email
   8.2 ............ Developer Forums
   8.3 ............ Mailinglist
  9.0 ............. Contact
  10.0 ............ Donating


1. Installation:
----------------

./configure && make

You will find the static and dynamic libraries in the directory libtool
will have created off of the libspf src dir.:

Example: ./libspf-1_0_0/src/libpf/.libs/

You will find the libSPF Query Tool binaries (both static and dynamic) in 
a directory created by make in the libSPF root directory called 'bin'.

Example: ./libspf-1_0_0/bin/

Outside of the generic available configure options you have the following
at your disposal:


--enable-pthreads  - Default = disabled

Enable linux posix threading support which in turn switches from gethostbyname
to gethostbyname_r (if available, if not a custom reentrant wrapper is used)
and several mutexes are employed to facilitate a thread-safe environment.


--enable-spfmilter - Default = disabled

Enable the libSPF fork of Jef Poskanzer's Sendmail spfmilter.  The milter was
forked at version 0.90.  Problems with the milter are NOT to be directed to 
Jef as its not fair to ask him to support a fork when he is plenty busy with
his own.  Please forward bugs, questions, etc.. to myself (James).


--enable-spfqtool - Default = enabled

Enable the libSPF Query Tool.  spfqtool is a fully functional binary SPF 
parser which you can call from userland or even call from a CGI or your
MTA if you so wished.  Since its written in the same language as libSPF 
its very lightweight and inexpensive to call repeatedly. 

The above switches also work in reverse, so if for example you wished
to disable to building of the query tool you would do:

./configure --disable-spfqtool


--enable-debug    - Default = disabled

Enable debugging output.  For a detailed document on how debugging works
within libSPF please see the internal documenation or the online document
available at http://libSPF.org/debugging_libspf.pdf/html  By default 
debug output is pushed to /var/log/spf.log.  If you wish to change this see
the AutoConf configuration handle '--enable-debug-logfile' and disable it.


--enable-debug-logfile - Default = enabled

Enables logging debug output to /var/log/spf.log


--enable-logfile-stats - Default = disabled

Enables logfile stats to /var/log/spflog.txt which look like this:

[2005-04-18 14:24:48] result: unknown :: NievNeal3864@jlist.com [82.120.84.13], ver: 10, depth: 1, error: (policy result: (unknown) from rule (-all))
[2005-04-18 14:24:48] result: unknown :: NievNeal3864@jlist.com [82.120.84.13], ver: 10, depth: 1, error: (policy result: (unknown) from rule (-all))
[2005-04-18 17:10:49] result: softfail :: emgdxfwavxzwhk@hotmail.com [201.15.156.75], ver: 5, depth: 1, error: (policy result: (softfail) from rule (~all))
[2005-04-18 21:14:00] result: neutral :: test@spftools.infinitepenguins.net [220.117.245.29], ver: 2, depth: 1, error: (policy result: (neutral) from rule (?all))
[2005-04-18 21:14:07] result: neutral :: test@spftools.infinitepenguins.net [220.117.245.29], ver: 2, depth: 1, error: (policy result: (neutral) from rule (?all))

I've got code to do this to MySQL if anyone is interested.. I'll try to 
include it in subsequent releases to 1.0 final.


--enable-rfc-recursion - Default = disabled

Change SPF recursion to 20 (as per RFC).  This level has been deemed by members
of the SPF-DISCUSS mailing list to be excessively high, although as far as I 
know Meng still believes it to be reasonable.  I personally believe that its
excessive, at least for now, which is why I've added this option to re-enable
RFC recursion limits.


--enable-res_search - Default = disasbled

Enables DNS queries to follow default and search rules.  This turned out to cause
all sorts of problems for people who were employing default and search fules in
their resolv.conf and was causing SPF queries to return improper results.  Its 
honestly a bit of a feature if you are aware of it, and since most people never
seem to read documentation or be aware of their surroundings, this is disabled
by default.


--enable-paranoid-malloc - Default = enabled

Enable memsetting of every malloc called through the wrapper functions
through wrapper functions that handle memory allocation.


--enable-libbind - Default = disabled

Link libbind instead of libresolv


--enable-full-optimizations - Default = disabled [DEPRECATED]

Enables building of an optimized library through the employment of various GCC
compile time macros.  I currently advise against this as they are architecture
specific but in the future it is intended that they will be intelligent and
will result in the right set of macros to result in the most optimized code
generated for whatever architecture it is compiled on. [DEPRECATED]


2. Patches: 
-----------

Patches for each respective supported MTA are found within the patches
directory, followed by the name of the MTA, and then optionally should
there have been support long enough, there will be where applicable 
additional directories per MAJOR.MINOR.INCREMENTAL.  

Example: ./libspf-1_0_0/patches/Sendmail/8.13.x/

The above example contains patches against Sendmail 8.13.x (the x is literal)
and infers that a patch against any 8.13 version will be located there.


3. Examples:
------------
  
Examples follow the same layout as Patches.  The examples directory contains
example configuration files for the various MTA's supported by libSPF.

Example: ./libspf-1_0_0/examples/Sendmail/8.13.x/sendmail.cf.example


4. Documentation:
-----------------

Documentation also follows the same layout as Patches and examples.  The
Documentation directory is called 'docs' and is also found in the root of the
unpack libspf archive.  Documentation is split up into two categories.


  4.1 MTA specific documentation:
  -------------------------------

  There is a basic HOWTO document which details step-by-step how to patch and
  install a copy of the respective MTA's supported by libSPF.  The documents
  follow the following naming convention:
  
  <mta>-<mta_version>-libspf-<libspf_version>-HOWTO.[html|txt|pdf]
  
  Example: ./libspf-1_0_0/docs/qmail/net-1.05/netqmail-1.05-libspf-1.0-HOWTO.txt
  
  
  4.2 API specific documentation:
  -------------------------------
 
  API specific documentation is found in the 'API' directory inside of the
  'docs' directory.  You can point your favorite web browser to this folder
  or simply use your favorite shell or file explorer to traverse through the
  content.
  
  The primary support for learning the API can be had through the HTML doxygen
  content available within each release of libSPF starting with libSPF-1.0-RC3,
  and the most up to date version will always be available from the libSPF.org 
  website.
  
  Secondary documentation is available from within this directory structure also
  and consists of papers that will go into specific detail on a particular
  topic.
  
  Example: ./libspf-1_0_0/docs/API/debugging_libspf.pdf


  4.3 Resources:
  --------------
  
  Please see the section entitled "libSPF Resources"
  
  
5.0 Source code:
----------------

All source code can be found from within the 'src' directory off the root of
the unpacked libspf 1.0 archive.  From there each individual library or 
binary will be located in its own directory.

Example: ./libspf-1_0_0/src/libspf


6.0 License:
------------
    
libSPF is released under our own license, which is a modified version of the
Apache Software Foundation's license.  This license was chosen because we* wanted
SPF implemented as fast and as easily as possible, and it was felt that licensing 
under the GPL would inhibit use by commertial entities wishing to support
something like SPF but being unable to do so due to a restrictive license such
as the GPL.

*we (Sean Comeau and myself)

License: ./libspf-1_0_0/LICENSE 


7.0 Portability:
----------------
   
libSPF is coded in accordance with the ANSI C/89 and ANSI C/99 Standards.  The
library entirely complies with C/89, and I had to move to employ standards
from C/99 to facilitate the debugging and standard function replacements that
are implemented.  For more information please read "Debugging libSPF" which can
be found within the archive this README was enclosed in, inside of the 'docs'
directory off its root.

libSPF is easily portable to win32 although because windows has not been the
focus of interest its lagged behind more important things such as API
documentation and getting near a stable release.  If win32 portability 
interests you feel free to contact me, all thats necessary is to finish off
a patch altering the DNS functionality.

libSPF is known to 'configure', 'compile' and work on the following
architectures and the distributions associated with them:

 [+--------------------------------------------------------------------------+]
  | Architecture | Distro         | Version  | Kernel    | Compiler Version |
  [+-------------+----------------+----------+-----------+------------------+] 
   | x86         | Fedora Core    | 1        | 2.6.3     | GCC 3.3.2        |
   | x86_64      | Fedora Core    | 1        | 2.6.7     | GCC 3.3.4 #$     |
   | x86         | Fedora Core    | 2        | 2.6.7     | GCC 3.3.3/4      |
   | x86_64      | Fedora Core    | 2        | 2.6.7     | GCC 3.3.3/4 #$   |
   | x86_64      | Fedora Core    | 3        | 2.6.11    | GCC 3.4.3   #$   |
   | x86         | Gentoo         | 1.4      | 2.6.7     | GCC 3.3.3/4 @#$  |
   | x86_64      | Gentoo         | 2004.1   | 2.6.7-r11 | GCC 3.3.3/4 @#$  |
   | x86_64      | Gentoo         | 2005.1   | 2.6.10-g6 | GCC 3.4.3   @#$  | 
   | x86         | Mandrake       | 9.2      | ?         | GCC 3.3.1        |
   | x86         | Slackware      | 8.0      | 2.6.7     | GCC 2.95.3       |
   | x86         | Slackware      | 8.1      | 2.6.7     | GCC 2.95.3       |
   | x86         | Slackware      | 9.0      | 2.6.7     | GCC 3.2.2        |
   | x86         | Slackware      | 9.1      | 2.6.7     | GCC 3.3.1        |
   | x86         | Slackware      | 10.0     | 2.6.7     | GCC 3.3.4        |
   | x86         | Red Hat Linux  | 3.2.3-34 | 2.4.21-15 | GCC 3.2.3 030502 | 
  [+-------------+----------------+----------+-----------+------------------+] 
   | x86         | OpenBSD        | 3.5      | 3.5       | GCC 2.95.3 @     |
   | x86_64      | OpenBSD        | 3.5      | 3.5       | GCC 2.95.3 @     |
   | x86         | FreeBSD        | 4.4      | 4.4       | GCC 2.95.3       |
   | x86         | FreeBSD        | 4.10-PRE | 4.10-PRE  | GCC 2.95.4       | 
   | x86         | FreeBSD        | 4.11-STA | 4.11-STAB | GCC 2.95.4       |
   | x86         | FreeBSD        | 5.3      | 5.3       | GCC ??????       |
  [+-------------+----------------+----------+-----------+------------------+] 
   | PPC         | OSX/Darwin     | 10.3     | 10.3      | GCC 3.3          | 
  [+-------------+----------------+----------+-----------+------------------+] 
   | SPARC       | SunOS/Solaris  | 5.8/8.0  | 5.8/8.0   | GCC/SC 3.0.1/5.3 |
   | x86         | SunOS/Solaris  | 5.8/8.0  | 5.8/8.0   | GCC 2.95.3       | 
   | SPARC       | SunOS/Solaris  | 5.9/9.0  | 5.9/9.0   | GCC 3.3          |
   | x86         | SunOS/Solaris  | 5.9/9.0  | 5.9/9.0   | GCC/SC 3.3.2/5.5 | 
  [+-------------+----------------+----------+-----------+------------------+]
  | @ = Propolice # = ssp $ = pie | Submit: <libspf-support@codeshare.ca>    |
 [+--------------------------------------------------------------------------+]


8.0 Resources:
--------------

I've tried to provide as much support as I can through the means at my disposal.
This being said you have access to the following:

  8.1 Email:
  ----------    
      
      I'm readily available via E-Mail both on and off the list to help answer
      any questions that are not blatantly answered through a little reading.
      
      If you are a developer looking to implement and have a question, bug,
      feature, idea, etc.. DO NOT HESITATE to contact me!
      
      If you are an Administrator and you are trying to implement libSPF on
      your network, and you have exhausted the available help, DO NOT 
      HESITATE to contact me!
      
      Contact E-Mail: jcouzens@codeshare.ca
      
      
  8.2 Developer Forums:
  ---------------------
      
      The developer forums are aimed to promoting further patch work implementing
      libSPF in other MTA's and in other ways.  Its also a venue of bug-fix
      releases and feature-testing.  
      
      Developers will find this site most useful, but this doesn't exclude any 
      particular party from participating, all are welcome to be involved.
      
      Developer Foruyms: http://forums.codeshare.ca
     
  8.3 Mailing List:
  -----------------
  
      As of August 1, 2004 there is now a mailing list hosted by codeshare.ca
      entitled 'libspf'.  You can subscribe to this mailginglist quite easily
      by submitting an email to 'libspf-subscribe@codeshare.ca' with an empty
      body and the subject: 'libspf subscribe'.

      There is also an announcesments list which is 'receive only' in that 
      only libSPF developers will post to it in announcement of a new
      release or bugfix.  To subscriber to this list submit and email to
      'libspf-announce-subscribe@codeshare.ca' with an empty body and the 
      subject: 'libspf announce subscribe'.

      
9.0 Contact:
------------
    
Forums ....................... http://forums.codeshare.ca
WWW .......................... http://libspf.org
Bugs ......................... James Couzens <jcouzens@codeshare.ca>


10.0 Donations:
---------------

Honestly the best donation you can give is to provide feedback,
patches, or aide the project in one fashion or another.  If you
do wish to show your appreciation in a more tangible form, I
personally enjoy books and small electronic devices which you 
can find on my Amazon wishlist.

http://libspf.org/wishlist.html 

Link seems to break from time to time, so if it does you could
search for my name if you were so motivated, or drop me a line :)

UPDATED: Mon Apr 18 21:32:45 PDT 2005

EOF
