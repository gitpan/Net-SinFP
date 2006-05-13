#
# $Id: SinFP6.pm,v 1.11.2.6.2.1 2006/05/13 10:56:00 gomor Exp $
#
package Net::SinFP::SinFP6;
use strict;
use warnings;

use Net::SinFP qw(/MATCH_ALGORITHM_*/);
our @ISA = qw(Net::SinFP);
__PACKAGE__->cgBuildIndices;

use Net::Pkt;

=head1 NAME

Net::SinFP::SinFP6 - IPv6 OS fingerprinting

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

sub new {
   my $self = shift->SUPER::new(@_);
   $self->target(getHostIpv6Addr($self->target)) if $self->target;
   $self;
}

sub startOffline {
   my $self = shift;

   my $dst = $self->_startOfflineGetDump;

   for ($self->_dump->frames) {   
      next unless $dst ne $Env->ip6;
      next unless $_->isIp;

      if (length($_->raw) == 74 && $_->l4->haveFlagSyn && ! $_->l4->haveFlagAck
      &&  ! $self->testSyn1Pkt) {
         $self->testSyn1Pkt($_);
         next;
      }   

      if (length($_->raw) == 94 && $_->l4->haveFlagSyn && ! $_->l4->haveFlagAck
      &&  ! $self->testSyn2Pkt) {
         $self->testSyn2Pkt($_);
         next;
      }

      if (length($_->raw) == 74 && $_->l4->haveFlagSyn && $_->l4->haveFlagAck
      &&  ! $self->testSynAPkt) {
         $self->testSynAPkt($_);
         next;
      }
   }

   $self->_startOfflineGetResponses;
}

sub _buildSig {
   my $self = shift;
   my ($first, $second) = @_;

   my ($sig, $opts, $mss) = $self->_buildSigFromOptions($first, $second);
   return $sig unless $first;

   unless (defined $second) {
      $sig = 'B1';
   }
   else {
      $sig =
         sprintf("B%d", $first->l3->hopLimit == $second->l3->hopLimit ? 1 : 0);
   }

   $sig .= sprintf("%d%d%d%d F0x%02x W%d ",
      $first->l3->trafficClass ? 1 : 0,
      $first->l3->flowLabel    ? 1 : 0,
      $first->l4->seq ? 1 : 0,
      $first->l4->ack ? 1 : 0,
      $first->l4->flags,
      $first->l4->win,
   );

   $self->_buildSigFinal($sig, $first, $opts, $mss);
}


my $tcpSrc = getRandom16bitsInt() - 3;
$tcpSrc += 1025 unless $tcpSrc > 1024;

my $tcpSeq = getRandom32bitsInt() - 3;
$tcpSeq += 666 unless $tcpSeq > 0;

my $tcpAck = getRandom32bitsInt() - 3;
$tcpAck += 666 unless $tcpAck > 0;

sub testSyn1Build {
   my $self = shift;

   my $eth = Net::Packet::ETH->new(
      type => NP_ETH_TYPE_IPv6,
      dst  => $self->mac,
   );

   my $ip6 = Net::Packet::IPv6->new(
      version      => 6,
      trafficClass => 0,
      flowLabel    => 0,
      nextHeader   => NP_IPv6_PROTOCOL_TCP,
      hopLimit     => 0xff,
      dst          => $self->target,
   );

   my $tcp = Net::Packet::TCP->new(
      src   => $tcpSrc,
      dst   => $self->port,
      seq   => $tcpSeq,
      ack   => $tcpAck,
      x2    => 0,
      flags => NP_TCP_FLAG_SYN,
      win   => 5840,
   );

   $self->testSyn1Pkt(
      Net::Packet::Frame->new(l2 => $eth, l3 => $ip6, l4 => $tcp)
   );
}

sub testSyn2Build {
   my $self = shift;

   my $eth = Net::Packet::ETH->new(
      type => NP_ETH_TYPE_IPv6,
      dst  => $self->mac,
   );

   my $ip6 = Net::Packet::IPv6->new(
      version      => 6,
      trafficClass => 0,
      flowLabel    => 0,
      nextHeader   => NP_IPv6_PROTOCOL_TCP,
      hopLimit     => 0xff,
      dst          => $self->target,
   );

   my $tcp = Net::Packet::TCP->new(
      src     => ++$tcpSrc,
      dst     => $self->port,
      seq     => ++$tcpSeq,
      ack     => ++$tcpAck,
      x2      => 0,
      flags   => NP_TCP_FLAG_SYN,
      win     => 5840,
      options =>
         "\x02\x04\x05\xb4".
         "\x08\x0a\x44\x45".
         "\x41\x44\x00\x00".
         "\x00\x00\x03\x03".
         "\x01\x04\x02\x00".
         "",
   );

   $self->testSyn2Pkt(
      Net::Packet::Frame->new(l2 => $eth, l3 => $ip6, l4 => $tcp)
   );
}

sub testSynABuild {
   my $self = shift;

   my $eth = Net::Packet::ETH->new(
      type => NP_ETH_TYPE_IPv6,
      dst  => $self->mac,
   );

   my $ip6 = Net::Packet::IPv6->new(
      version      => 6,
      trafficClass => 0,
      flowLabel    => 0,
      nextHeader   => NP_IPv6_PROTOCOL_TCP,
      hopLimit     => 0xff,
      dst          => $self->target,
   );

   my $tcp = Net::Packet::TCP->new(
      src   => ++$tcpSrc,
      dst   => $self->port,
      seq   => ++$tcpSeq,
      ack   => ++$tcpAck,
      x2    => 0,
      flags => NP_TCP_FLAG_SYN | NP_TCP_FLAG_ACK,
      win   => 5840,
   );

   $self->testSynAPkt(
      Net::Packet::Frame->new(l2 => $eth, l3 => $ip6, l4 => $tcp)
   );
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
