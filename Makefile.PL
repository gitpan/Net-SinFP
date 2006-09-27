#
# $Id: Makefile.PL,v 1.4.2.12.2.4 2006/06/11 09:42:17 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'lib/Net/SinFP.pm',
   ABSTRACT_FROM => 'lib/Net/SinFP.pm',
   PREREQ_PM     => {
      Net::Packet          => '3.00',
      Net::Packet::Target  => 0,
      Class::Gomor         => 0,
      DBIx::SQLite::Simple => '0.33',
   },
   EXE_FILES => [ 'bin/sinfp.pl', 'bin/sinfp.db', ],
   AUTHOR    => 'GomoR <sinfp@gomor.org>',
);
