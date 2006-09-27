#
# $Id: Result.pm,v 1.1.2.6 2006/06/12 21:30:27 gomor Exp $
#
package Net::SinFP::Result;
use strict;
use warnings;

require Class::Gomor::Array;
our @ISA = qw(Class::Gomor::Array);

our @AS = qw(
   idSignature
   ipVersion
   systemClass
   vendor
   os
   osVersion
   osVersionFamily
   matchType
   matchMask
);
our @AA = qw(
   osVersionChildrenList
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);
__PACKAGE__->cgBuildAccessorsArray (\@AA);

1;

=head1 NAME

Net::SinFP::Result - contains all information about matched fingerprint

=head1 DESCRIPTION

Go to http://www.gomor.org/sinfp to know more.

=cut

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
