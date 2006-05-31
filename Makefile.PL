#
# $Id: Makefile.PL,v 1.4.2.9.2.2 2006/05/31 16:51:05 gomor Exp $
#
use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'lib/Net/SinFP.pm',
   ABSTRACT_FROM => 'lib/Net/SinFP.pm',
   PREREQ_PM     => {
      Net::Packet          => '2.22',
      DBIx::SQLite::Simple => '0.32',
      Class::Gomor         => 0,
   },
   EXE_FILES => [ 'bin/sinfp.pl', 'bin/sinfp.db',
                  'bin/np-anon-pcap.pl', 'bin/np-read-anon.pl',
                ],
   AUTHOR    => 'GomoR <sinfp@gomor.org>',
);
