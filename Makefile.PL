use ExtUtils::MakeMaker;

if ($>) {
   warn("*** You are not root, installation of sinfp.db will not be done.\n".
        "*** Please copy manually sinfp.db into /usr/local/share/sinfp/.\n\n");
}
else {
   # Create directory for sinfp.db and copy it into
   mkdir('/usr/local',             755) unless -d '/usr/local';
   mkdir('/usr/local/share',       755) unless -d '/usr/local/share';
   mkdir('/usr/local/share/sinfp', 755) unless -d '/usr/local/share/sinfp';

   # Also create local bin directory for sinfp.pl and np-anon-pcap.pl
   mkdir('/usr/local/bin', 755) unless -d '/usr/local/bin';

   if (-d '/usr/local/share/sinfp') {
      open(my $dst, '>', '/usr/local/share/sinfp/sinfp.db')
         or die("Can't open /usr/local/share/sinfp/sinfp.db for writing: $!\n");
      open(my $src, '<', 'sinfp.db')
         or die("Can't open sinfp.db for reading: $!\n");
      print $dst $_ for <$src>;
      close($src);
      close($dst);
   }
}

WriteMakefile(
   NAME          => 'Net::SinFP',
   VERSION_FROM  => 'SinFP.pm',
   PREREQ_PM     => {
      Net::Packet          => '2.06',
      Class::Gomor::Hash   => '0.22',
      DBIx::SQLite::Simple => '0.30',
   },
   INSTALLBIN    => '/usr/local/bin',
   EXE_FILES     => [ 'sinfp.pl', 'np-anon-pcap.pl', 'np-read-anon.pl', ],
   ABSTRACT_FROM => 'SinFP.pm',
   AUTHOR        => 'GomoR <sinfp@gomor.org>',
);
