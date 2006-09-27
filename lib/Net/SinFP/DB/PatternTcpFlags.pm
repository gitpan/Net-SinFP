#
# $Id: PatternTcpFlags.pm,v 1.1.2.12.2.3 2006/06/11 17:18:53 gomor Exp $
#
package Net::SinFP::DB::PatternTcpFlags;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idPatternTcpFlags
   patternTcpFlagsHeuristic0
   patternTcpFlagsHeuristic1
   patternTcpFlagsHeuristic2
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

our $Id     = $AS[0];
our @Fields = @AS[1..$#AS];

1;

=head1 NAME

Net::SinFP::DB::PatternTcpFlags - PatternTcpFlags database table

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
