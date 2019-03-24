#!/usr/bin/perl
#
#  File: test.pl
#  Author: James Couzens <jcouzens@codeshare.ca> (Maintainer)
#  Author: Wayne Schlitt <wayne@midwestcs.com> (Author)
#  Author: Meng Weng Wong <mengwengwong@pobox.com> (Original Author)
#  
#  Desc:  
#          Originally designed to stress test any SPF implementation however
#  this particular implementation has long since been updated with any of Wayne's
#  code since he has added many "features" to his library which I disagree with.
#  We don't need features at this stage, we need stable code.  Quite frankly,
#  we don't need any features, we just need what the RFC states.
#
# Date: 01/25/04  - based on the perl Mail-SPF-Query-1.99.tar
# Date: 07/28/04  - Edit to use to spfqtool
# Date: 10/07/04  - cleaned this mess up, no wonder people think perl is ugly
#
#########################

use Test;
use strict;

use Getopt::Long;

my $HELP     = 0;
my $SPFPROG  = "./spfqtool_static";
my $SPFDATA  = "test.txt";
my $VALGRIND = '/usr/bin/valgrind';
my $VG_OPTS  = '--log-file=vg_test.txt --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=50 --trace-children=yes';


my $result = GetOptions(
  'help'      => \$HELP,
  'program=s' => \$SPFPROG,
  'data=s'    => \$SPFDATA,
);

if ($HELP  || !$result)
{
  print <<EOF;
Usage: apmiser [options]

      -help	Help on the options.

      -program=/path/program  Use an alternate spfqtool command.
      -data=/path/test.txt    Use an alternate alternate test data
EOF
  exit(0);
}


my @test_table;

BEGIN
{
  open(TESTFILE, "test.txt");

  @test_table = grep
                {
                  /\S/ and not /^\s*#/
                } <TESTFILE>;

  chomp @test_table;
  close(TESTFILE);

  plan tests => (1 + @test_table);
};

# 1: did the library load okay?
ok(1);

#########################

foreach my $tuple (@test_table)
{
  my ($num,
      $domain,
      $ipv4,
      $expected_result,
      $expected_smtp_comment,
      $expected_header_comment) = $tuple =~ /\t/ ? split(/\t/, $tuple) :
                                                    split(' ', $tuple);

  my ($sender, $localpolicy) = split(':', $domain, 2);

  $sender =~ s/\\([0-7][0-7][0-7])/chr(oct($1))/ge;
  $domain = $sender;

  if ($domain =~ /\@/)
  {
    ($domain) = $domain =~ /\@(.+)/
  }

  if ($expected_result =~ /=(pass | fail),/)
  {
    print "these tests are not implemented yet.\n";

    for (my $debug = 0; $debug < 2; $debug++)
    {
      last;

      my $query = "";

      my $ok = 1;
      my $header_comment;

      foreach my $e_result (split(/,/, $expected_result))
      {
        if ($e_result !~ /=/)
        {
          my ($msg_result, $smtp_comment);

          ($msg_result, $smtp_comment, $header_comment) =
            eval
            {
              $query->message_result2
            };

          # its this kind of code that makes people hate perl !@($*_#!
          $ok = ok($msg_result, $e_result) if (!$debug);

          if (!$ok)
          {
            last;
          }
        }
        else
        {
          my ($recip, $expected_recip_result) = split(/=/, $e_result, 2);

          my ($recip_result, $smtp_comment) =
            eval
            {
              $query->result2(split(';',$recip))
            };

            $ok = ok($recip_result, $expected_recip_result) if (!$debug);

            if (!$ok)
            {
              last;
            }
        } # else
      } # foreach

      $header_comment =~ s/\S+: //; # strip the reporting hostname prefix

      if ($expected_header_comment)
      {
          $ok &= ok($header_comment, $expected_header_comment) if (!$debug);
      }

      last if ($ok);
    } # foreach
    
  } # if expected result
  else
  {
    open(SPFQUERY, "$SPFPROG -i \"$ipv4\" -s \"$sender\" -h \"$domain\" -z 1 |");

    my ($result, $smtp_comment, $header_comment);

    chomp($result         = <SPFQUERY>);
    chomp($smtp_comment   = <SPFQUERY>);
    chomp($header_comment = <SPFQUERY>);

    close(SPFQUERY);

    $header_comment =~ s/^\S+: //; # strip the reporting hostname prefix

    print "bin/spfqtool_static -i $ipv4 -s $sender -h $domain -z 1\n";

    my $ok = (! $expected_smtp_comment
              ?  ok($result, $expected_result)
              : (ok($result, $expected_result) &&
                 ok($smtp_comment, $expected_smtp_comment) &&
                 ok($header_comment, $expected_header_comment)));

    if (not $ok)
    {
       print "./spfqtool_static -i \"$ipv4\" -s \"$sender\" -h \"$domain\" -z 1 |\n";

       printf "Result:         %s\n", $result;
       printf "SMTP comment:   %s\n", $smtp_comment;
       printf "Header comment: %s\n", $header_comment;

       open(SPFQUERY, "$SPFPROG -i \"$ipv4\" -s \"$sender\" -h \"$domain\" -z 1 |");

       while(<SPFQUERY>)
       {
         print $_;
       }

      close(SPFQUERY);

      if ($@)
      {
        print "  trapped error: $@\n";
        next;
      }
    } # if (not $ok)
  } # else
} # foreach

# end of test.pl
