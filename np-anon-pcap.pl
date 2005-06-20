#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Std;
my %opts;
getopts('f:', \%opts);
die("Usage: $0 -f pcapFile\n") unless $opts{f};

use Net::Pkt;

my $in = Net::Packet::Dump->new(
   file            => $opts{f},
   overwrite       => 0,
   unlinkOnDestroy => 0,
   callStart       => 0,
   noEnvSet        => 1,
);

$in->nextAll;

my $src = ($in->frames)[0]->l3->src;
for ($in->frames) {
   if ($_->l3->src eq $src) {
      $_->l3->src('127.0.0.1');
      $_->l3->dst('127.0.0.2');
   }
   else {
      $_->l3->src('127.0.0.2');
      $_->l3->dst('127.0.0.1');
   }
   $_->noPadding(1);
   $_->pack;
   my $raw = $_->l3->raw;
   $raw .= $_->l4->raw if $_->l4;
   $raw .= $_->l7->raw if $_->l7;
   print "@{[$_->l3->is]}: ", unpack('H*', $raw), "\n";
}
