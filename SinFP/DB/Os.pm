#
# $Id: Os.pm,v 1.1.2.11 2006/03/11 19:30:25 gomor Exp $
#

package Net::SinFP::DB::Os;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idOs
   os
);
__PACKAGE__->buildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::Os - Os SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idOs);
our @Fields = qw(os);

sub getOs { shift->lookupString('os', idOs => shift) }

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
