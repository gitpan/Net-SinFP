use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'SinFP.pm',
   PREREQ_PM     => {
      Net::Packet          => '2.03',
      Class::Gomor::Hash   => '0.20',
      DBIx::SQLite::Simple => '0.30',
   },
   ABSTRACT_FROM => 'SinFP.pm',
   AUTHOR        => 'GomoR <sinfp@gomor.org>',
);
