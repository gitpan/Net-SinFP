#
# $Id: PatternTcpMss.pm,v 1.1.2.10.2.1 2006/05/13 10:57:50 gomor Exp $
#
package Net::SinFP::DB::PatternTcpMss;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idPatternTcpMss
   patternTcpMss
   patternTcpMssHeuristic1
   patternTcpMssHeuristic2
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

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

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
