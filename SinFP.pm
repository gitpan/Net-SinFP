#
# $Id: SinFP.pm,v 1.8.2.29 2006/03/13 12:28:36 gomor Exp $
#

package Net::SinFP;

use strict;
use warnings;

our $VERSION = '1.00';

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
   keepPcap
   _dump
   _db
   _tPatternBinary
   _tPatternTcpFlags
   _tPatternTcpWindow
   _tPatternTcpOptions
   _tPatternTcpMss
   _tSystemClass
   _tVendor
   _tOs
   _tOsVersion
   _tOsVersionChildren
);
our @AA = qw(
   osfps
   _signatures
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

sub new {
   my $self = shift->SUPER::new(
      offline  => 0,
      wait     => 3,
      retry    => 3,
      found    => 0,
      passive  => 0,
      h2Match  => 0,
      osfps    => [],
      dbFile   => '/usr/local/share/sinfp/sinfp.db',
      keepPcap => 0,
      _db      => 0,
      @_,
   );

   $self->_db(DBIx::SQLite::Simple->new(db => $self->dbFile))
      or die("Can't open db: ". $self->dbFile. "\n");

   $self->_loadSignatures;

   $self;
}

sub _lookupOsInfos {
   my $self = shift;
   my $s = shift;

   # Lookup values
   $s->systemClass($self->_tSystemClass->getSystemClass($s->idSystemClass));
   $s->vendor($self->_tVendor->getVendor($s->idVendor));
   $s->os($self->_tOs->getOs($s->idOs));
   $s->osVersion($self->_tOsVersion->getOsVersion($s->idOsVersion));

   my $osVersionChildren = $self->_tOsVersionChildren->select(
      idSignature => $s->idSignature,
   );

   if (@$osVersionChildren) {
      my @osVersion;
      push @osVersion, $self->_tOsVersion->getOsVersion($_->idOsVersion)
         for @$osVersionChildren;
      $s->osVersionChildren(\@osVersion);
   }
   else {
      $s->osVersionChildren([]);
   }
}

sub _lookupPatterns {
   my $self = shift;
   my $s = shift;

   for my $t ('1', '2', '3') {
      for my $m ('PatternBinary', 'PatternTcpFlags', 'PatternTcpWindow', 
                 'PatternTcpOptions', 'PatternTcpMss') {
         my $table = '_t'.$m;
         my $g = $m;
         $g =~ s/^Pattern/get/;
         my $m1   = 't'.$t.$m;
         my $m2   = $g;
         my $m3   = 'idT'.$t.$m;
         my $m1h1 = 't'.$t.$m.'H1';
         my $m2h1 = $g.'H1';
         my $m1h2 = 't'.$t.$m.'H2';
         my $m2h2 = $g.'H2';
         $s->$m1  ($self->$table->$m2  ($s->$m3));
         $s->$m1h1($self->$table->$m2h1($s->$m3));
         $s->$m1h2($self->$table->$m2h2($s->$m3));
      }
   }
}

sub _loadSignatures {
   my $self = shift;

   # Tables only used locally
   my $tSignature = Net::SinFP::DB::Signature->new;
   my $tIpVersion = Net::SinFP::DB::IpVersion->new;

   # Tables used in other methods
   $self->_tPatternBinary    (Net::SinFP::DB::PatternBinary->new);
   $self->_tPatternTcpFlags  (Net::SinFP::DB::PatternTcpFlags->new);
   $self->_tPatternTcpWindow (Net::SinFP::DB::PatternTcpWindow->new);
   $self->_tPatternTcpOptions(Net::SinFP::DB::PatternTcpOptions->new);
   $self->_tPatternTcpMss    (Net::SinFP::DB::PatternTcpMss->new);

   $self->_tSystemClass      (Net::SinFP::DB::SystemClass->new);
   $self->_tVendor           (Net::SinFP::DB::Vendor->new);
   $self->_tOs               (Net::SinFP::DB::Os->new);
   $self->_tOsVersion        (Net::SinFP::DB::OsVersion->new);
   $self->_tOsVersionChildren(Net::SinFP::DB::OsVersionChildren->new);

   my $idIpVersion;
   my ($class) = ref($self) =~ /^(?:.*::)?(.*)/;

   ($class eq 'SinFP4')
      ? ($idIpVersion = $tIpVersion->getIdIpVersion('IPv4'))
      : ($idIpVersion = $tIpVersion->getIdIpVersion('IPv6'));
   my $signatures = $tSignature->select(idIpVersion => $idIpVersion);
   die("Unable to load signatures from sinfp.db.\n".
       "Try installing latest DBD::SQLite module.\n")
      unless scalar @$signatures;

   $self->_lookupPatterns($_) for @$signatures;

   $self->_signatures($signatures);
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
      unlinkOnDestroy => $self->keepPcap ? 0 : 1,
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

         return if $self->testSyn1Pkt->reply
                && $self->testSyn2Pkt->reply
                && $self->testSynAPkt->reply;
      }

      $Env->dump->timeout(0);
   }
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

   my $s1 = $self->testSyn1Sig if $self->testSyn1Pkt
                               && $self->testSyn1Pkt->reply;
   my $s2 = $self->testSyn2Sig if $self->testSyn2Pkt
                               && $self->testSyn2Pkt->reply;
   my $sA = $self->testSynASig if $self->testSynAPkt
                               && $self->testSynAPkt->reply;

   for my $s ($self->_signatures) {
      my $t1;
      my $t2;
      my $t3;
      if ($type eq SIGNATURE_TYPE_EXACT) {
         $t1 = $s->t1PatternBinary.' '.$s->t1PatternTcpFlags.' '.
               $s->t1PatternTcpWindow.' '.$s->t1PatternTcpOptions.' '.
               $s->t1PatternTcpMss;
         $t2 = $s->t2PatternBinary.' '.$s->t2PatternTcpFlags.' '.
               $s->t2PatternTcpWindow.' '.$s->t2PatternTcpOptions.' '.
               $s->t2PatternTcpMss;
         $t3 = $s->t3PatternBinary.' '.$s->t3PatternTcpFlags.' '.
               $s->t3PatternTcpWindow.' '.$s->t3PatternTcpOptions.' '.
               $s->t3PatternTcpMss;
         $s->signatureType(SIGNATURE_TYPE_EXACT);
      }
      elsif ($type eq SIGNATURE_TYPE_HEURISTIC1) {
         $t1 = $s->t1PatternBinaryH1.' '.$s->t1PatternTcpFlagsH1.' '.
               $s->t1PatternTcpWindowH1.' '.$s->t1PatternTcpOptionsH1.' '.
               $s->t1PatternTcpMssH1;
         $t2 = $s->t2PatternBinaryH1.' '.$s->t2PatternTcpFlagsH1.' '.
               $s->t2PatternTcpWindowH1.' '.$s->t2PatternTcpOptionsH1.' '.
               $s->t2PatternTcpMssH1;
         $t3 = $s->t3PatternBinaryH1.' '.$s->t3PatternTcpFlagsH1.' '.
               $s->t3PatternTcpWindowH1.' '.$s->t3PatternTcpOptionsH1.' '.
               $s->t3PatternTcpMssH1;
         $s->signatureType(SIGNATURE_TYPE_HEURISTIC1);
      }
      elsif ($type eq SIGNATURE_TYPE_HEURISTIC2) {
         $t1 = $s->t1PatternBinaryH2.' '.$s->t1PatternTcpFlagsH2.' '.
               $s->t1PatternTcpWindowH2.' '.$s->t1PatternTcpOptionsH2.' '.
               $s->t1PatternTcpMssH2;
         $t2 = $s->t2PatternBinaryH2.' '.$s->t2PatternTcpFlagsH2.' '.
               $s->t2PatternTcpWindowH2.' '.$s->t2PatternTcpOptionsH2.' '.
               $s->t2PatternTcpMssH2;
         $t3 = $s->t3PatternBinaryH2.' '.$s->t3PatternTcpFlagsH2.' '.
               $s->t3PatternTcpWindowH2.' '.$s->t3PatternTcpOptionsH2.' '.
               $s->t3PatternTcpMssH2;
         $s->signatureType(SIGNATURE_TYPE_HEURISTIC2);
      }

      # In passive mode, the SYN2 test is not our own, so timestamp is not 
      # built as we want. We rewrite it to be able to match.
      if ($self->passive) {
         $t2 =~ s/44454144/......../;
      }

      # Matching is done here
      if (($s1 && $s1 =~ /^$t1$/)
      &&  ($s2 && $s2 =~ /^$t2$/)
      &&  ($sA && $sA =~ /^$t3$/)) {
         $s->matchAlgorithm(MATCH_ALGORITHM_FULL);
         $self->_lookupOsInfos($s);
         $self->_addResult($s);
         $self->found(1);
      }
      elsif (($s1 && $s1 =~ /^$t1$/)
         &&  ($s2 && $s2 =~ /^$t2$/)) {
         $s->matchAlgorithm(MATCH_ALGORITHM_TWO); # Firewalled system
         $self->_lookupOsInfos($s);
         $self->_addResult($s);
         $self->found(1);
      }
      elsif ($s2 && $s2 =~ /^$t2$/) { # Match only with test 2
         $s->matchAlgorithm(MATCH_ALGORITHM_ONE);
         $self->_lookupOsInfos($s);
         $self->_addResult($s);
         $self->found(1);
      }
   }

   $self->found;
}

sub _cleanFound {
   my $self = shift;

   my $betterAlgo = MATCH_ALGORITHM_ONE;
   for ($self->osfps) {
      if ($_->matchAlgorithm eq MATCH_ALGORITHM_FULL) {
         $betterAlgo = MATCH_ALGORITHM_FULL;
         last;
      }
      elsif ($_->matchAlgorithm eq MATCH_ALGORITHM_TWO) {
         $betterAlgo = MATCH_ALGORITHM_TWO;
      }
   }

   my $h = {
      MATCH_ALGORITHM_FULL() => 3,
      MATCH_ALGORITHM_TWO()  => 2,
      MATCH_ALGORITHM_ONE()  => 1,
   };

   my @keep = ();
   for ($self->osfps) {
      if ($h->{$_->matchAlgorithm} >= $h->{$betterAlgo}) {
         push @keep, $_;
      }
   }
   $self->osfps(\@keep);
   $self->found(scalar @keep);
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

   # Keep only better MATCH_ALGORITHM from all results found
   # Otherwise, it is possible to have a FULL match, and a FIREWALLED 
   # match, and we do not want that.
   $self->_cleanFound;
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
   my $self = shift;
   $self->_dump->stop if $self->_dump && $self->_dump->isRunning;
   $self->_db->close  if $self->_db;
   return(0);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
