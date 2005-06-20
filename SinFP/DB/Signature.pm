#
# $Id: Signature.pm,v 1.1.2.9 2005/06/16 19:45:05 gomor Exp $
#

package Net::SinFP::DB::Signature;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idSignature
   idIpVersion
   idSystemClass
   idVendor
   idOs
   idOsVersion
   idT1PatternBinary
   idT1PatternTcpFlags
   idT1PatternTcpWindow
   idT1PatternTcpOptions
   idT1PatternTcpMss
   idT2PatternBinary
   idT2PatternTcpFlags
   idT2PatternTcpWindow
   idT2PatternTcpOptions
   idT2PatternTcpMss
   idT3PatternBinary
   idT3PatternTcpFlags
   idT3PatternTcpWindow
   idT3PatternTcpOptions
   idT3PatternTcpMss

   matchAlgorithm
   signatureType
   ipVersion
   systemClass
   vendor
   os
   osVersion
);
my @AA = qw(
   osVersionChildren
);
__PACKAGE__->buildAccessorsScalar(\@AS);
__PACKAGE__->buildAccessorsArray(\@AA);

=head1 NAME

Net::SinFP::DB::Signature - Signature SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idSignature);
our @Fields = qw(
   idIpVersion idSystemClass idVendor idOs idOsVersion 
   idT1PatternBinary idT1PatternTcpFlags idT1PatternTcpWindow
   idT1PatternTcpOptions idT1PatternTcpMss idT2PatternBinary
   idT2PatternTcpFlags idT2PatternTcpWindow idT2PatternTcpOptions
   idT2PatternTcpMss idT3PatternBinary idT3PatternTcpFlags idT3PatternTcpWindow
   idT3PatternTcpOptions idT3PatternTcpMss
);

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
