#
# $Id: Makefile.PL,v 1.4.2.12.2.6 2006/11/18 12:43:49 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'lib/Net/SinFP.pm',
   ABSTRACT_FROM => 'lib/Net/SinFP.pm',
   LICENSE       => 'Artistic',
   PREREQ_PM     => {
      Net::Packet          => '3.20',
      Net::Packet::Target  => 0,
      Class::Gomor         => 0,
      DBIx::SQLite::Simple => '0.33',
   },
   EXE_FILES => [ 'bin/sinfp.pl', 'bin/sinfp.db', ],
   AUTHOR    => 'GomoR <sinfp@gomor.org>',
);
