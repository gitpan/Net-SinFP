#
# $Id: Signature.pm,v 1.1.2.11.2.1 2006/05/13 10:57:50 gomor Exp $
#
package Net::SinFP::DB::Signature;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

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

   t1PatternBinary
   t1PatternTcpFlags
   t1PatternTcpWindow
   t1PatternTcpOptions
   t1PatternTcpMss
   t2PatternBinary
   t2PatternTcpFlags
   t2PatternTcpWindow
   t2PatternTcpOptions
   t2PatternTcpMss
   t3PatternBinary
   t3PatternTcpFlags
   t3PatternTcpWindow
   t3PatternTcpOptions
   t3PatternTcpMss
   t1PatternBinaryH1
   t1PatternTcpFlagsH1
   t1PatternTcpWindowH1
   t1PatternTcpOptionsH1
   t1PatternTcpMssH1
   t2PatternBinaryH1
   t2PatternTcpFlagsH1
   t2PatternTcpWindowH1
   t2PatternTcpOptionsH1
   t2PatternTcpMssH1
   t3PatternBinaryH1
   t3PatternTcpFlagsH1
   t3PatternTcpWindowH1
   t3PatternTcpOptionsH1
   t3PatternTcpMssH1
   t1PatternBinaryH2
   t1PatternTcpFlagsH2
   t1PatternTcpWindowH2
   t1PatternTcpOptionsH2
   t1PatternTcpMssH2
   t2PatternBinaryH2
   t2PatternTcpFlagsH2
   t2PatternTcpWindowH2
   t2PatternTcpOptionsH2
   t2PatternTcpMssH2
   t3PatternBinaryH2
   t3PatternTcpFlagsH2
   t3PatternTcpWindowH2
   t3PatternTcpOptionsH2
   t3PatternTcpMssH2
);
our @AA = qw(
   osVersionChildren
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray(\@AA);

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

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
