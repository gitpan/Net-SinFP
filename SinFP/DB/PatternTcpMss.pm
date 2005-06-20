#
# $Id: PatternTcpMss.pm,v 1.1.2.9 2005/06/16 19:45:05 gomor Exp $
#

package Net::SinFP::DB::PatternTcpMss;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idPatternTcpMss
   patternTcpMss
   patternTcpMssHeuristic1
   patternTcpMssHeuristic2
);
__PACKAGE__->buildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::PatternTcpMss - PatternTcpMss SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idPatternTcpMss);
our @Fields = qw(patternTcpMss patternTcpMssHeuristic1 patternTcpMssHeuristic2);

sub getTcpMss { shift->lookupString('patternTcpMss', idPatternTcpMss => shift) }
sub getTcpMssH1 {
   shift->lookupString('patternTcpMssHeuristic1', idPatternTcpMss => shift);
}
sub getTcpMssH2 {
   shift->lookupString('patternTcpMssHeuristic2', idPatternTcpMss => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
