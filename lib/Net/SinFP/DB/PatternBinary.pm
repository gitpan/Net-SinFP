#
# $Id: PatternBinary.pm,v 1.1.2.10.2.2 2006/05/31 16:49:57 gomor Exp $
#
package Net::SinFP::DB::PatternBinary;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idPatternBinary
   patternBinary
   patternBinaryHeuristic1
   patternBinaryHeuristic2
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::PatternBinary - PatternBinary SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/sinfp to know more.

=cut

our $Id     = qw(idPatternBinary);
our @Fields = qw(patternBinary patternBinaryHeuristic1 patternBinaryHeuristic2);

sub getBinary { shift->lookupString('patternBinary', idPatternBinary => shift) }
sub getBinaryH1 {
   shift->lookupString('patternBinaryHeuristic1', idPatternBinary => shift);
}
sub getBinaryH2 {
   shift->lookupString('patternBinaryHeuristic2', idPatternBinary => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
