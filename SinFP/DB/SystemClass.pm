#
# $Id: SystemClass.pm,v 1.1.2.10 2005/06/16 19:45:05 gomor Exp $
#

package Net::SinFP::DB::SystemClass;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idSystemClass
   systemClass
);
__PACKAGE__->buildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::SystemClass - SystemClass SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idSystemClass);
our @Fields = qw(systemClass);

sub getSystemClass {
   shift->lookupString('systemClass', idSystemClass => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
