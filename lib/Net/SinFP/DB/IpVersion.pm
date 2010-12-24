#
# $Id: IpVersion.pm 1659 2010-12-24 12:24:19Z gomor $
#
package Net::SinFP::DB::IpVersion;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idIpVersion
   ipVersion
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

our $Id     = $AS[0];
our @Fields = @AS[1..$#AS];

sub getIdIpVersion { shift->lookupId(ipVersion => shift)                    }
sub getIpVersion   { shift->lookupString('ipVersion', idIpVersion => shift) }

1;

=head1 NAME

Net::SinFP::DB::IpVersion - IpVersion database table

=head1 DESCRIPTION

Go to http://www.gomor.org/sinfp to know more.

=cut

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2010, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut
