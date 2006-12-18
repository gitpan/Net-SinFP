#
# $Id: Makefile.PL,v 1.4.2.12.2.7 2006/12/18 15:36:56 gomor Exp $
#
use ExtUtils::MakeMaker;

require v5.6.1;

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
