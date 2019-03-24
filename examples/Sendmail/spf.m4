divert(-1)
#
# Written 2004 Teddy
#
# Checks the SPF records of sending domain
#
divert(0)
ifdef(`_SPF_',`dnl',`dnl
VERSIONID(`$Id: spf.m4,v 1.1 2007/11/13 00:51:35 root Exp $')
divert(-1)
define(`_SPF_',`')')dnl
define(`confSPFAction',ifelse(len(X`'_ARG_),`1',`1',_ARG_))dnl
define(`confSPFHeaderState',ifelse(len(X`'_ARG2_),`1',`True',_ARG2_))dnl
define(`confSPFBestGuessState',ifelse(len(X`'_ARG3_),`1',`0',_ARG3_))dnl
define(`confSPFTrustedForwarderState',ifelse(len(X`'_ARG4_),`1',`0',_ARG4_))dnl
define(`confSPFExplainState',ifelse(len(X`'_ARG5_),`1',`True',_ARG5_))dnl
define(`confSPFBestGuess',ifelse(len(X`'_ARG6_),`1',`v=spf1 a/24 mx/24 ptr',_ARG6_))dnl
define(`confSPFTrustedForwarder',ifelse(len(X`'_ARG7_),`1',`v=spf1 include:spf.trusted-forwarder.org',_ARG7_))dnl
define(`confSPFExplain',ifelse(len(X`'_ARG8_),`1',`See http://spf.pobox.com/why.html?sender=%{S}&ip=%{I}&receiver=%{xR}',_ARG8_))dnl
divert(8)
# Checks the SPF records of sending domain
R$*			$: $1  $| <?>$&{spfreject}<?>
R$* $| <?>1<?>		$#error $@ 5.7.1 $: "550 Mail from [" $&{client_addr} "] Rejected. " $&{spfexplain}
R$* $| <?>$*		$: $1
divert(-1)
