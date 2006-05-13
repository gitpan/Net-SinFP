#
# $Id: PatternTcpWindow.pm,v 1.1.2.10.2.1 2006/05/13 10:57:50 gomor Exp $
#
package Net::SinFP::DB::PatternTcpWindow;
use strict;
use warnings;

require DBIx::SQLite::Simple::Table;
our @ISA = qw(DBIx::SQLite::Simple::Table);

our @AS = qw(
   idPatternTcpWindow
   patternTcpWindow
   patternTcpWindowHeuristic1
   patternTcpWindowHeuristic2
);
__PACKAGE__->cgBuildIndices;
__PACKAGE__->cgBuildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::PatternTcpWindow - PatternTcpWindow SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idPatternTcpWindow);
our @Fields = qw(
   patternTcpWindow patternTcpWindowHeuristic1 patternTcpWindowHeuristic2
);

sub getTcpWindow {
   shift->lookupString('patternTcpWindow', idPatternTcpWindow => shift);
}
sub getTcpWindowH1 {
   shift->lookupString('patternTcpWindowHeuristic1', idPatternTcpWindow => shift);
}
sub getTcpWindowH2 {
   shift->lookupString('patternTcpWindowHeuristic2', idPatternTcpWindow => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005-2006, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See LICENSE.Artistic file in the source distribution archive.

=cut

1;
