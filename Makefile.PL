#
# $Id: Makefile.PL 1659 2010-12-24 12:24:19Z gomor $
#
use ExtUtils::MakeMaker;

require v5.6.1;

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'lib/Net/SinFP.pm',
   ABSTRACT_FROM => 'lib/Net/SinFP.pm',
   LICENSE       => 'artistic',
   PREREQ_PM     => {
      Net::Packet          => '3.20',
      Net::Packet::Target  => 0,
      Class::Gomor         => 0,
      DBIx::SQLite::Simple => '0.33',
   },
   EXE_FILES => [ 'bin/sinfp.pl', 'bin/sinfp.db', ],
   AUTHOR    => 'GomoR <gomor-cpan_at_gomor.org>',
);
