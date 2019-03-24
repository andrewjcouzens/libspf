#------------------------------------------------------------------------------
#
#          oooo   o8o   .o8        .oooooo..o ooooooooo.   oooooooooooo
#          `888   `"'  "888       d8P'    `Y8 `888   `Y88. `888'     `8
#           888  oooo   888oooo.  Y88bo.       888   .d88'  888
#           888  `888   d88' `88b  `"Y8888o.   888ooo88P'   888oooo8
#           888   888   888   888      `"Y88b  888          888    "
#           888   888   888   888 oo     .d8P  888          888
#          o888o o888o  `Y8bod8P' 8""88888P'  o888o        o888o
#
#-------------------------------------------------------------------------------
#           An ANSI C Implementation of the Sender Policy Framework
#-------------------------------------------------------------------------------
#
# File:   Makefile.am 
# Author: James Couzens <jcouzens@codeshare.ca>
# Date:   June 15, 2004  
# Info:   Makefile base for Autotools for the libSPF library
# ------------------------------------------------------------------------------

AUTOMAKE_OPTIONS = foreign

# ------------------------------------------------------------------------------
# Compiler Flags 
# ------------------------------------------------------------------------------

if  GCC
AM_CFLAGS   = -D_BSD_SOURCE
endif

# ------------------------------------------------------------------------------
# Build subdirectoriee
# ------------------------------------------------------------------------------

SUBDIRS    = src
EXTRA_DIST = \
	docs/spfqtool \
	docs/qmail \
	docs/qmail/1.03 \
	docs/qmail/1.04 \
	docs/qmail/1.05 \
	docs/Sendmail  \
	docs/Sendmail/8.12.x \
	docs/Sendmail/8.13.x \
	docs/Postfix \
	docs/Postfix/2.1.x \
	docs/Courier-MTA \
	docs/API \
	docs/RFC \
	docs/README \
	docs/history \
	build_tools/bewm.sh \
	examples \
	examples/qmail \
	examples/Sendmail \
	patches \
	patches/Courier-MTA \
	patches/qmail \
	patches/Sendmail \
	patches/Sendmail/8.12.x \
	patches/Sendmail/8.13.x \
	patches/Postfix \
	patches/Postfix/2.1.x \
	patches/README \
	AUTHORS \
	README \
	FAQ \
	VERSION \
	LICENSE \
	CHANGELOG

# ------------------------------------------------------------------------------
# LIBTOOL dependancies
# ------------------------------------------------------------------------------

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

distclean-generic:
	rm -rf ./bin
	rm -rf ./lib
	rm -f Makefile
	rm -f src/spfmilter/Makefile
	rm -rf src/spfmilter/.deps
	rm -f stamp*

clean-local:
	@[ -d ./bin ] || rm -rf ./bin
	@[ -d ./lib ] || rm -rf ./lib
	rm -f stamp*


# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------

test :
	if test -x "/usr/bin/perl"; then \
		cd src/spfqtool; \
    /usr/bin/perl test.pl; \
	elif test -x "/usr/local/bin/perl"; then \
		cd src/spfqtool; \
    /usr/local/bin/perl test.pl; \
	elif test -x "/bin/perl"; then \
		cd src/spfqtool; \
    /bin/perl test.pl; \
	fi;


# ------------------------------------------------------------------------------
# test_valgrind
# ------------------------------------------------------------------------------

test_valgrind :
	if test -x "/usr/bin/perl"; then \
		cd src/spfqtool; \
    /usr/bin/perl test_valgrind.pl; \
	elif test -x "/usr/local/bin/perl"; then \
		cd src/spfqtool; \
    /usr/local/bin/perl test_valgrind.pl; \
	elif test -x "/bin/perl"; then \
		cd src/spfqtool; \
    /bin/perl test_valgrind.pl; \
	fi;

# end of Makefile.am
