#!/usr/bin/perl
#
# $Id: np-read-anon.pl,v 1.1.2.1.2.1 2006/05/13 10:53:10 gomor Exp $
#
use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use Getopt::Std;
my %opts;
getopts('Hf:', \%opts);

die("Usage: $0 -f anon-file.txt\n") unless $opts{f};

use Net::Pkt;
$Env->debug(3);

open(my $file, '<', $opts{f}) or die("open: $opts{f}: $!\n");

$Env->link(0);

my $dump = Net::Packet::Dump->new(
   callStart => 0,
   overwrite => 0,
   unlinkOnDestroy => 0,
);

my $ip;
my $count = 0;
while (<$file>) {
   chomp;
   if (/^IPv(\d):\s+(.*)?$/) {
      my $raw = $2;
      $ip = $1;

      my $frame = Net::Packet::Frame->new(raw => pack('H*', $raw));

      $dump->framesSorted($frame);
      my @frames = $dump->frames;
      push @frames, $frame;
      $dump->frames(\@frames);
   }
}
close($file);

my $sinfp;
if ($ip == 4) {
   use Net::SinFP::SinFP4;

   $sinfp = Net::SinFP::SinFP4->new(
      offline => 1,
      h2Match => $opts{H} ? 1 : 0,
   );

   my $dst = ($dump->frames)[0]->l3->dst;

   for ($dump->frames) {
      next unless $dst ne '127.0.0.1';

      if ($_->l3->length == 40 && $_->l4->haveFlagSyn && ! $_->l4->haveFlagAck
      &&  ! $sinfp->testSyn1Pkt) {
         $sinfp->testSyn1Pkt($_);
         next;
      }

      if ($_->l3->length == 60 && $_->l4->haveFlagSyn && ! $_->l4->haveFlagAck
      &&  ! $sinfp->testSyn2Pkt) {
         $sinfp->testSyn2Pkt($_);
         next;
      }

      if ($_->l3->length == 40 && $_->l4->haveFlagSyn && $_->l4->haveFlagAck
      &&  ! $sinfp->testSynAPkt) {
         $sinfp->testSynAPkt($_);
         next;
      }
   }

   $sinfp->testSyn1Pkt && $sinfp->testSyn1Pkt->recv;
   $sinfp->testSyn2Pkt && $sinfp->testSyn2Pkt->recv;
   $sinfp->testSynAPkt && $sinfp->testSynAPkt->recv;

   $sinfp->analyzeReponses;
   $sinfp->matchOsfps;
   $sinfp->printResults;
}
else {
   print "Not IPv4\n";
}
