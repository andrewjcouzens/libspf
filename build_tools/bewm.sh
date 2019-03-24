#!/bin/sh
#
# File:   bewm.sh
# Author: James Couzens <jcouzens@codeshare.ca>
# Date:   November 18, 2004
#
# Desc:
#         Because autotools and autoconf etc.. generate such obscenly huge
# and disgusting shell output, you should run this script to call the 
# appropriate userland tools to generate the necessary autotools shell 
# scripts such that you can then run 'configure' and 'make' etc...
#

AL='/usr/bin/aclocal-1.6'
AH='/usr/bin/autoheader-2.59'
AC='/usr/bin/autoconf-2.59'
AM='/usr/bin/automake-1.6'

if test -x $AL; then
  echo "Calling aclocal ($AL)...";
  $AL
else
  echo "Unable to execute ($AL) or it doesn't exist...";
  exit -1;
fi

if test -x $AH; then
  echo "Calling autoheader ($AH)...";
  $AH
else
  echo "Unable to execute ($AH) or it doesn't exist...";
  exit -1;
fi

if test -x $AC; then
  echo "Calling autoconf ($AC)...";
  $AC
else
  echo "Unable to execute ($AC) or it doesn't exist...";
  exit -1;
fi

if test -x $AM; then
  echo "Calling automake ($AM)...";
  $AM
else
  echo "Unable to execute ($AM) or it doesn't exist...";
  exit -1;
fi

echo "Done!";
