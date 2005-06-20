#
# $Id: PatternTcpOptions.pm,v 1.1.2.9 2005/06/16 19:45:05 gomor Exp $
#

package Net::SinFP::DB::PatternTcpOptions;

require DBIx::SQLite::Simple::Table;
require Class::Gomor::Hash;
our @ISA = qw(DBIx::SQLite::Simple::Table Class::Gomor::Hash);

our @AS = qw(
   idPatternTcpOptions
   patternTcpOptions
   patternTcpOptionsHeuristic1
   patternTcpOptionsHeuristic2
);
__PACKAGE__->buildAccessorsScalar(\@AS);

=head1 NAME

Net::SinFP::DB::PatternTcpOptions - PatternTcpOptions SQL table

=head1 DESCRIPTION

Go to http://www.gomor.org/ to know more.

=cut

our $Id     = qw(idPatternTcpOptions);
our @Fields = qw(
   patternTcpOptions patternTcpOptionsHeuristic1 patternTcpOptionsHeuristic2
);

sub getTcpOptions {
   shift->lookupString('patternTcpOptions', idPatternTcpOptions => shift);
}
sub getTcpOptionsH1 {
   shift->lookupString('patternTcpOptionsHeuristic1', idPatternTcpOptions => shift);
}
sub getTcpOptionsH2 {
   shift->lookupString('patternTcpOptionsHeuristic2', idPatternTcpOptions => shift);
}

=head1 AUTHOR

Patrice E<lt>GomoRE<gt> Auffret

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005, Patrice E<lt>GomoRE<gt> Auffret

You may distribute this module under the terms of the Artistic license.
See Copying file in the source distribution archive.

=cut

1;
