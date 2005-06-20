#
# $Id: PatternBinary.pm,v 1.1.2.9 2005/06/16 19:45:05 gomor Exp $
#

package Net::SinFP::DB::PatternBinary;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idPatternBinary
   patternBinary
   patternBinaryHeuristic1
   patternBinaryHeuristic2
);
__PACKAGE__->buildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::PatternBinary - PatternBinary SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

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

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
