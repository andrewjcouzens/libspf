# ------------------------------------------------------------------------------
# File:   Makefile.am 
# Author: James Couzens <jcouzens@6o4.ca>
# Date:   June 15, 2004  
# Info:   Makefile base for Autotools for the SPF Query tool (libSPF) 
# ------------------------------------------------------------------------------

AUTOMAKE_OPTIONS = foreign

if  GCC
AM_CFLAGS = -Wall -ggdb3 -D_GNU_SOURCE -D_BSD_SOURCE
else
AM_CFLAGS = -D_GNU_SOURCE -D_BSD_SOURCE
endif
AM_CPPFLAGS =

# ------------------------------------------------------------------------------
# Directories
# ------------------------------------------------------------------------------

spftopdir = ../libspf
spflibdir = ../libspf/.libs


# ------------------------------------------------------------------------------
# Includes
# ------------------------------------------------------------------------------

INCLUDES    = -I$(spflibdir) -I$(spftopdir)
EXTRA_DIST  = spfqtool.h test.pl test.txt


# ------------------------------------------------------------------------------
# Programs to make
# ------------------------------------------------------------------------------

bin_PROGRAMS  = spfqtool spfqtool_static


# ------------------------------------------------------------------------------
# Dynamically linked build
# ------------------------------------------------------------------------------

spfqtool_SOURCES = spfqtool.c
spfqtool_LDADD  = $(spftopdir)/libspf.la @LIBSPF_PTHREADS_LIB@


# ------------------------------------------------------------------------------
# STATIC build
# ------------------------------------------------------------------------------

spfqtool_static_SOURCES = spfqtool.c
spfqtool_static_LDADD = $(spflibdir)/libspf.a
spfqtool_static_LDFLAGS = -static @LIBSPF_RESOLV_LIB@ @LIBSPF_PTHREADS_LIB@


# ------------------------------------------------------------------------------
# all
# ------------------------------------------------------------------------------

all-local:
	@[ -d ../../bin ] || mkdir ../../bin
	$(MAKE) DESTDIR= bindir=`pwd`/../../bin install-exec


# ------------------------------------------------------------------------------
# clean
# ------------------------------------------------------------------------------

clean-local:
	@[ -d ../../bin ] || rm -rf ../../bin


# ------------------------------------------------------------------------------
#  test 
# ------------------------------------------------------------------------------

test:
	perl test.pl

.PHONY : test

# end of Makefile.am
