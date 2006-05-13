#
# $Id: IpVersion.pm,v 1.1.2.12.2.1 2006/05/13 10:57:50 gomor Exp $
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

=head1 NAME

Net::SinFP::DB::IpVersion - IpVersion SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idIpVersion);
our @Fields = qw(ipVersion);

sub getIdIpVersion { shift->lookupId(ipVersion => shift)                    }
sub getIpVersion   { shift->lookupString('ipVersion', idIpVersion => shift) }

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
