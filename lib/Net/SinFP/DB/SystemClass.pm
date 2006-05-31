#
# $Id: SystemClass.pm,v 1.1.2.11.2.2 2006/05/31 16:49:57 gomor Exp $
#
package Net::SinFP::DB::SystemClass;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idSystemClass
   systemClass
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::SystemClass - SystemClass SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/sinfp to know more.

=cut

our $Id     = qw(idSystemClass);
our @Fields = qw(systemClass);

sub getSystemClass {
   shift->lookupString('systemClass', idSystemClass => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
