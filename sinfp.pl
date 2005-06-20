#!/usr/bin/perl

#
# $Id: sinfp.pl,v 1.1.2.8 2005/06/20 21:42:59 gomor Exp $
#

use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('d:i:I:p:r:t:f:v46m:M:PF:HOs:', \%opts);

die("\n  -- SinFP - $Net::SinFP::VERSION --\n".
    "\n".
    "Usage: sinfp.pl -i targetIp [-p openTcpPort] [-d device] [-f pcapFile]\n".
    "       [-I sourceIp] [-r retryNumber] [-t timeout] [-v]\n".
    "       [-m targetMac (for IPv6)] [-M sourceMac (for IPv6)]\n".
    "       [-s signatureFile]\n".
    "       [-4 | -6]\n".
    "       [-P] [-F filter]\n".
    "       [-H]\n".
    "       [-O]\n".
    "\n".
    "       -4: default, use IPv4 fingerprinting\n".
    "       -6: use IPv6 fingerprinting\n".
    "       -P: passive fingerprinting\n".
    "       -F: pcap filter for passive fingerprinting\n".
    "       -H: use HEURISTIC2 mode to match signatures\n".
    "           (mostly used as a human helper, or for passive OSFP)\n".
    "       -O: print only operating system\n".
    "")
   unless (($opts{i} && !$opts{6})
        || ($opts{i} && $opts{6} && $opts{m})
        || ($opts{f})
        || ($opts{P}));

$opts{p} = 80 unless $opts{p};
$opts{4} = 1  unless $opts{6};

use Net::Pkt;

$Env->dev($opts{d}) if $opts{d};
$Env->ip ($opts{I}) if $opts{I} && $opts{4};
$Env->ip6($opts{I}) if $opts{I} && $opts{6};
$Env->mac($opts{M}) if $opts{M};
$Env->debug(3)      if $opts{v};

my $dbFile;
if ($opts{s}) {
   $dbFile = $opts{s};
}
else {
   my @paths = qw(./ /usr/local/share/sinfp/);
   for (@paths) {
      $dbFile = $_. 'sinfp.db' if -f $_. 'sinfp.db';
   }
}

my $sinfp;
if ($opts{4}) {
   use Net::SinFP::SinFP4;

   $sinfp = Net::SinFP::SinFP4->new(
      retry   => $opts{r} ? $opts{r} : 3,
      wait    => $opts{t} ? $opts{t} : 3,
      offline => $opts{f} ? 1 : 0,
      target  => $opts{i},
      port    => $opts{p},
      passive => $opts{P} ? 1 : 0,
      h2Match => $opts{H} ? 1 : 0,
      filter  => $opts{F},
      dbFile  => $dbFile,
   );
}
else {
   use Net::SinFP::SinFP6;

   $sinfp = Net::SinFP::SinFP6->new(
      retry   => $opts{r} ? $opts{r} : 3,
      wait    => $opts{t} ? $opts{t} : 3,
      offline => $opts{f} ? 1 : 0,
      target  => $opts{i},
      port    => $opts{p},
      mac     => $opts{m},
      passive => $opts{P} ? 1 : 0,
      h2Match => $opts{H} ? 1 : 0,
      filter  => $opts{F},
      dbFile  => $dbFile,
   );
}

$sinfp->file($opts{f}) if $opts{f};

if (!$sinfp->passive) {
   $sinfp->offline
      ? $sinfp->startOffline
      : $sinfp->startOnline;

   $sinfp->analyzeReponses;
   $sinfp->matchOsfps;
   $opts{O}
      ? $sinfp->printResultsOnlyOs
      : $sinfp->printResults
   ;
}
else {
   $sinfp->offline
      ? $sinfp->startOfflinePassive
      : $sinfp->startOnlinePassive;
}
