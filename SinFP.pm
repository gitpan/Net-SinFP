#
# $Id: SinFP.pm,v 1.8.2.23 2005/06/20 21:43:45 gomor Exp $
#

package Net::SinFP;

use strict;
use warnings;

our $VERSION = '0.92';

require Exporter;
require Class::Gomor::Hash;
our @ISA = qw(Exporter Class::Gomor::Hash);

our @EXPORT_OK = qw(
   MATCH_ALGORITHM_FULL
   MATCH_ALGORITHM_TWO
   MATCH_ALGORITHM_ONE
   SIGNATURE_TYPE_EXACT
   SIGNATURE_TYPE_HEURISTIC1
   SIGNATURE_TYPE_HEURISTIC2

   SIGNATURE_TYPE_INCOMPLETE
);

use constant MATCH_ALGORITHM_FULL      => 'FULL';
use constant MATCH_ALGORITHM_TWO       => 'FIREWALLED';
use constant MATCH_ALGORITHM_ONE       => 'ONE PACKET';
use constant SIGNATURE_TYPE_EXACT      => 'EXACT';
use constant SIGNATURE_TYPE_HEURISTIC1 => 'HEURISTIC1';
use constant SIGNATURE_TYPE_HEURISTIC2 => 'HEURISTIC2';

our @AS = qw(
   target
   port
   mac
   found
   file
   wait
   retry
   h2Match
   offline
   passive
   filter
   testSyn1Pkt
   testSyn2Pkt
   testSynAPkt
   testSyn1Sig
   testSyn2Sig
   testSynASig
   dbFile
   _dump
);
our @AA = qw(
   osfps
);
__PACKAGE__->buildAccessorsScalar(\@AS);
__PACKAGE__->buildAccessorsArray(\@AA);

use Net::Pkt;
require DBIx::SQLite::Simple;
require Net::SinFP::DB::Signature;
require Net::SinFP::DB::IpVersion;
require Net::SinFP::DB::PatternBinary;
require Net::SinFP::DB::PatternTcpFlags;
require Net::SinFP::DB::PatternTcpWindow;
require Net::SinFP::DB::PatternTcpOptions;
require Net::SinFP::DB::PatternTcpMss;
require Net::SinFP::DB::SystemClass;
require Net::SinFP::DB::Vendor;
require Net::SinFP::DB::Os;
require Net::SinFP::DB::OsVersion;
require Net::SinFP::DB::OsVersionChildren;

=head1 NAME

Net::SinFP - a Perl module to do OS fingerprinting

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

my $db;

my $tSignature;
my $tIpVersion;
my $tPatternBinary;
my $tPatternTcpFlags;
my $tPatternTcpWindow;
my $tPatternTcpOptions;
my $tPatternTcpMss;
my $tSystemClass;
my $tVendor;
my $tOs;
my $tOsVersion;
my $tOsVersionChildren;

sub new {
   my $self = shift->SUPER::new(
      offline => 0,
      wait    => 3,
      retry   => 3,
      found   => 0,
      passive => 0,
      h2Match => 0,
      osfps   => [],
      @_,
   );

   $db = DBIx::SQLite::Simple->new(db => $self->dbFile)
      or die("Can't open db");

   $tSignature         = Net::SinFP::DB::Signature->new;
   $tIpVersion         = Net::SinFP::DB::IpVersion->new;
   $tPatternBinary     = Net::SinFP::DB::PatternBinary->new;
   $tPatternTcpFlags   = Net::SinFP::DB::PatternTcpFlags->new;
   $tPatternTcpWindow  = Net::SinFP::DB::PatternTcpWindow->new;
   $tPatternTcpOptions = Net::SinFP::DB::PatternTcpOptions->new;
   $tPatternTcpMss     = Net::SinFP::DB::PatternTcpMss->new;
   $tSystemClass       = Net::SinFP::DB::SystemClass->new;
   $tVendor            = Net::SinFP::DB::Vendor->new;
   $tOs                = Net::SinFP::DB::Os->new;
   $tOsVersion         = Net::SinFP::DB::OsVersion->new;
   $tOsVersionChildren = Net::SinFP::DB::OsVersionChildren->new;

   $self;
}

sub _printPassive {
   my $self = shift;
   my ($frame) = @_;

   print $frame->l3->src. ':'. $frame->l4->src. ' > '.
         $frame->l3->dst. ':'. $frame->l4->dst;

   $frame->l4->haveFlagAck ? print " [SYN|ACK]\n"
                           : print " [SYN]\n";

   # Do not try to match if there is not enough options
   if ($frame->l4->getOptionsLength <= 4) {
      print "Not enough TCP options, skipping\n\n";
      return undef;
   }

   # Rewrite TCP flags to be SinFP DB compliant
   $frame->l4->flags(NP_TCP_FLAG_SYN|NP_TCP_FLAG_ACK);
   $frame->l4->pack;

   $self->testSyn2Pkt($frame);
   $self->testSyn2Pkt->reply($frame);

   $self->testSyn2Sig($self->_buildSig($frame, undef));

   $self->matchOsfps;
   $self->printResults;
   print "\n";

   # Reset for next tries
   $self->found(0);
   $self->osfps([]);

   1;
}

sub startOnlinePassive {
   my $self = shift;

   my ($class) = ref($self) =~ /^(?:.*::)?(.*)/;

   my $file;
   my $filter;
   if ($class eq 'SinFP6') {
      $file   = 'sinfp6-passive.pcap';
      $filter = '(ip6 and tcp and ';
   }
   else {
      $file   = 'sinfp4-passive.pcap';
      $filter = '(ip and tcp and ';
   }
   $filter .= '((tcp[tcpflags] & tcp-syn != 0) and'.
              ' (tcp[tcpflags] & tcp-ack != 0)) or'.
              ' (tcp[tcpflags] & tcp-syn != 0))';

   my $dump = Net::Packet::Dump->new(
      file            => $file,
      unlinkOnDestroy => 0,
      overwrite       => 1,
      timeoutOnNext   => 0,
      callStart       => 0,
      noStore         => 1,
   );

   $self->filter ? $dump->filter('('. $self->filter. ') and '. $filter)
                 : $dump->filter($filter);

   $dump->start;

   $self->testSyn1Pkt(undef);
   $self->testSynAPkt(undef);

   while (1) {
      if (my $frame = $dump->next) {
         $self->_printPassive($frame);
      }
   }

   $dump->stop;
}

sub startOfflinePassive {
   my $self = shift;

   $self->_dump(
      Net::Packet::Dump->new(
         file            => $self->file,
         overwrite       => 0,
         unlinkOnDestroy => 0,
         callStart       => 0,
      ),
   );

   $self->_dump->nextAll;
   die("No frames captured\n") unless ($self->_dump->frames)[0];

   $self->testSyn1Pkt(undef);
   $self->testSynAPkt(undef);

   for my $frame ($self->_dump->frames) {
      if ($frame->l4->isTcp) {
         if ($frame->l4->flags == (NP_TCP_FLAG_SYN)
         ||  $frame->l4->flags == (NP_TCP_FLAG_SYN|NP_TCP_FLAG_ACK) ) {
            $self->_printPassive($frame);
         }
      }
   }
}

sub startOnline {
   my $self = shift;

   my ($class) = ref($self) =~ /^(?:.*::)?(.*)/;

   my $file;
   my $filter;
   if ($class eq 'SinFP6') {
      $file   = 'sinfp6-'. $self->target. '.'. $self->port. '.pcap';
      $filter = '(ip6 and host '. $self->target. ' and host '. $Env->ip6. ')';
   }
   else {
      $file   = 'sinfp4-'. $self->target. '.'. $self->port. '.pcap';
      $filter = 'host '. $self->target. ' and host '. $Env->ip;
   }

   my $dump = Net::Packet::Dump->new(
      file            => $file,
      unlinkOnDestroy => 0,
      overwrite       => 1,
      timeoutOnNext   => $self->wait,
      callStart       => 0,
   );

   $self->testSyn1Build;
   $self->testSyn2Build;
   $self->testSynABuild;

   $filter .= ' and tcp and port '. $self->port.
              ' and '.
              '(   port '. $self->testSyn1Pkt->l4->src.
              ' or port '. $self->testSyn2Pkt->l4->src.
              ' or port '. $self->testSynAPkt->l4->src.
              ')';
   $dump->filter($filter);

   $dump->start;

   for (1..$self->retry) {
      $self->testSyn1Pkt->send unless $self->testSyn1Pkt->reply;
      $self->testSyn2Pkt->send unless $self->testSyn2Pkt->reply;
      $self->testSynAPkt->send unless $self->testSynAPkt->reply;

      until ($Env->dump->timeout) {
         if ($dump->next) {
            $self->testSyn1Pkt->recv;
            $self->testSyn2Pkt->recv;
            $self->testSynAPkt->recv;
         }

         do { $dump->stop; return } if $self->testSyn1Pkt->reply
                                    && $self->testSyn2Pkt->reply
                                    && $self->testSynAPkt->reply;
      }

      $Env->dump->timeout(0);
   }

   $dump->stop;
}

sub _startOfflineGetDump {
   my $self = shift;

   $self->_dump(
      Net::Packet::Dump->new(
         file            => $self->file,
         overwrite       => 0,
         unlinkOnDestroy => 0,
         callStart       => 0,
      ),
   );

   $self->_dump->nextAll;

   die("No frames captured\n") unless ($self->_dump->frames)[0];
   ($self->_dump->frames)[0]->l3->dst;
}

sub _startOfflineGetResponses {
   my $self = shift;

   $self->testSyn1Pkt->recv if $self->testSyn1Pkt;
   $self->testSyn2Pkt->recv if $self->testSyn2Pkt;
   $self->testSynAPkt->recv if $self->testSynAPkt;

   $self->_dump->stop;
}

sub _buildSigFromOptions {
   my $self = shift;
   my ($first, $second) = @_;
   my $sig = 'B00000 F0 W0 O0 M0';

   return $sig unless $first;

   # Rewrite timestamp values, if > 0 overwrite with ffff, for each timestamp
   my $mss = 0;
   my $opts;
   if ($opts = unpack('H*', $first->l4->options)) {
      if ($opts =~ /080a(........)(........)/) {
         if ($1 && $1 !~ /44454144|00000000/) {
            $opts =~ s/(080a)........(........)/$1ffffffff$2/;
         }
         if ($2 && $2 !~ /44454144|00000000/) {
            $opts =~ s/(080a........)......../$1ffffffff/;
         }
      }
      # Move MSS value in its own field
      if ($opts =~ /0204(....)/) {
         if ($1) {
            $mss = sprintf("%d", hex($1));
            $opts =~ s/0204..../0204ffff/;
         }
      }
   }
   $opts = 0 unless $opts;

   ( $sig, $opts, $mss );
}

sub _buildSigFinal {
   my $self = shift;
   my ($sig, $first, $opts, $mss) = @_;

   $sig .= 'O'.$opts                      if     $opts;
   $sig .= unpack('H*', $first->l7->data) if     $first->l7;
   $sig .= 'O0'                           unless $opts || $first->l7;
   $sig .= " M$mss";

   $sig;
}

sub analyzeReponses {
   my $self = shift;

   $self->testSyn1Sig($self->_buildSig($self->testSyn1Pkt->reply, undef))
      if $self->testSyn1Pkt;
   $self->testSyn2Sig($self->_buildSig($self->testSyn2Pkt->reply, undef))
      if $self->testSyn2Pkt;
   $self->testSynASig(
      $self->_buildSig(
         $self->testSynAPkt->reply,
         $self->testSyn1Pkt->reply || $self->testSyn2Pkt->reply,
      ),
   ) if $self->testSynAPkt;
}

sub _addResult {
   my $self = shift;
   my ($result) = @_;

   my @new = $self->osfps;
   push @new, $result;

   $self->osfps(\@new);
}

sub _matchSig {
   my $self = shift;
   my ($type) = @_;

   my ($class) = ref($self) =~ /^(?:.*::)?(.*)/;

   my $signatures;
   if ($class eq 'SinFP6') {
      my $idIpVersion = $tIpVersion->getIdIpVersion('IPv6');
      $signatures = $tSignature->select(idIpVersion => $idIpVersion);
   }
   else {
      my $idIpVersion = $tIpVersion->getIdIpVersion('IPv4');
      $signatures = $tSignature->select(idIpVersion => $idIpVersion);
   }

   my $s1 = $self->testSyn1Sig if $self->testSyn1Pkt
                               && $self->testSyn1Pkt->reply;
   my $s2 = $self->testSyn2Sig if $self->testSyn2Pkt
                               && $self->testSyn2Pkt->reply;
   my $sA = $self->testSynASig if $self->testSynAPkt
                               && $self->testSynAPkt->reply;

   for my $s (@{$signatures}) {
      my $t1;
      my $t2;
      my $t3;
      if ($type eq SIGNATURE_TYPE_EXACT) {
         $t1 =
            $tPatternBinary->getBinary($s->idT1PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlags($s->idT1PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindow($s->idT1PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptions($s->idT1PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMss($s->idT1PatternTcpMss)
         ;
         $t2 =
            $tPatternBinary->getBinary($s->idT2PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlags($s->idT2PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindow($s->idT2PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptions($s->idT2PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMss($s->idT2PatternTcpMss)
         ;
         $t3 =
            $tPatternBinary->getBinary($s->idT3PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlags($s->idT3PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindow($s->idT3PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptions($s->idT3PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMss($s->idT3PatternTcpMss)
         ;
         $s->signatureType(SIGNATURE_TYPE_EXACT);
      }
      elsif ($type eq SIGNATURE_TYPE_HEURISTIC1) {
         $t1 =
            $tPatternBinary->getBinaryH1($s->idT1PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH1($s->idT1PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH1($s->idT1PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH1($s->idT1PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH1($s->idT1PatternTcpMss)
         ;
         $t2 =
            $tPatternBinary->getBinaryH1($s->idT2PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH1($s->idT2PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH1($s->idT2PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH1($s->idT2PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH1($s->idT2PatternTcpMss)
         ;
         $t3 =
            $tPatternBinary->getBinaryH1($s->idT3PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH1($s->idT3PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH1($s->idT3PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH1($s->idT3PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH1($s->idT3PatternTcpMss)
         ;
         $s->signatureType(SIGNATURE_TYPE_HEURISTIC1);
      }
      elsif ($type eq SIGNATURE_TYPE_HEURISTIC2) {
         $t1 =
            $tPatternBinary->getBinaryH2($s->idT1PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH2($s->idT1PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH2($s->idT1PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH2($s->idT1PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH2($s->idT1PatternTcpMss)
         ;
         $t2 =
            $tPatternBinary->getBinaryH2($s->idT2PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH2($s->idT2PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH2($s->idT2PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH2($s->idT2PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH2($s->idT2PatternTcpMss)
         ;
         $t3 =
            $tPatternBinary->getBinaryH2($s->idT3PatternBinary).' '.
            $tPatternTcpFlags->getTcpFlagsH2($s->idT3PatternTcpFlags).' '.
            $tPatternTcpWindow->getTcpWindowH2($s->idT3PatternTcpWindow).' '.
            $tPatternTcpOptions->getTcpOptionsH2($s->idT3PatternTcpOptions).' '.
            $tPatternTcpMss->getTcpMssH2($s->idT3PatternTcpMss)
         ;
         $s->signatureType(SIGNATURE_TYPE_HEURISTIC2);
      }

      if ($self->passive) {
         $t2 =~ s/44454144/......../;
      }

      # Lookup values
      $s->systemClass($tSystemClass->getSystemClass($s->idSystemClass));
      $s->vendor($tVendor->getVendor($s->idVendor));
      $s->os($tOs->getOs($s->idOs));
      $s->osVersion($tOsVersion->getOsVersion($s->idOsVersion));

      my $osVersionChildren = $tOsVersionChildren->select(
         idSignature => $s->idSignature,
      );

      if (@$osVersionChildren) {
         my @osVersion;
         push @osVersion, $tOsVersion->getOsVersion($_->idOsVersion)
            for @$osVersionChildren;
         $s->osVersionChildren(\@osVersion);
      }
      else {
         $s->osVersionChildren([]);
      }

      if ($s1 && $s2 && $sA
      &&  $s1 =~ /^$t1$/
      &&  $s2 =~ /^$t2$/
      &&  $sA =~ /^$t3$/) {
         $s->matchAlgorithm(MATCH_ALGORITHM_FULL);
         $self->_addResult($s);
         $self->found($self->found + 1);
      }
      elsif ($s1 && $s2 && ! $sA
      &&     $s1 =~ /^$t1$/
      &&     $s2 =~ /^$t2$/) {
         $s->matchAlgorithm(MATCH_ALGORITHM_TWO);
         $self->_addResult($s);
         $self->found($self->found + 1);
      }
      elsif (! $s1 && $s2 && ! $sA
      &&     $s2 =~ /^$t2$/) {
         $s->matchAlgorithm(MATCH_ALGORITHM_ONE);
         $self->_addResult($s);
         $self->found($self->found + 1);
      }
   }

   $self->found;
}

sub matchSigExact      { shift->_matchSig(SIGNATURE_TYPE_EXACT)      }
sub matchSigHeuristic1 { shift->_matchSig(SIGNATURE_TYPE_HEURISTIC1) }
sub matchSigHeuristic2 { shift->_matchSig(SIGNATURE_TYPE_HEURISTIC2) }

sub matchOsfps {
   my $self = shift;

   for (1..2) {
      $self->matchSigExact;
      $self->matchSigHeuristic1 if ! $self->found;
      $self->matchSigHeuristic2 if ! $self->found && $self->h2Match;

      last if $self->testSynAPkt && ! $self->testSynAPkt->reply
           || $self->found;

      # Remove testSynA (potentially firewall crafted), and retry
      $self->testSynAPkt && $self->testSynAPkt->reply(undef);
   }
}

sub _getIpVersion {
   my $self = shift;

   my ($class) = ref($self) =~ /^(?:.*::)?(.*)/;

   my $osfp;
   $class eq 'SinFP6'
      ? do { $osfp = 'IPv6' }
      : do { $osfp = 'IPv4' }
   ;

   $osfp;
}

sub _printSignature {
   my $self = shift;

   print 'T1: ', $self->testSyn1Sig, "\n" if $self->testSyn1Sig;
   print 'T2: ', $self->testSyn2Sig, "\n" if $self->testSyn2Sig;
   print 'T3: ', $self->testSynASig, "\n" if $self->testSynASig;
}

sub printResults {
   my $self = shift;

   my $osfp = $self->_getIpVersion;

   $self->_printSignature;

   for ($self->osfps) {
      print
         "$osfp: ". $_->signatureType. '/'. $_->matchAlgorithm.
         ': '. $_->systemClass.
         ': '. $_->vendor.
         ': '. $_->os.
         ': '. $_->osVersion
      ;

      if ($_->osVersionChildren) {
         my $buf = '';
         $buf .= $_.', ' for $_->osVersionChildren;
         $buf =~ s/, $//;
         print " ($buf)";
      }

      print "\n";
   }

   print "$osfp: unknown\n" unless $self->found;
}

sub printResultsOnlyOs {
   my $self = shift;

   my $osfp = $self->_getIpVersion;

   $self->_printSignature;

   my %os;
   do { $os{$_->os} = '' } for $self->osfps;
   print "$osfp: $_\n" for keys %os;

   print "$osfp: unknown\n" unless $self->found;
}

sub DESTROY {
   $Env->dump->stop if $Env->dump->isRunning;
   $db->close       if $db;
   exit(0);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
