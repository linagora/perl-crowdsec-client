use 5.036000;
use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME          => 'CrowdSec::Client',
    VERSION_FROM  => 'lib/CrowdSec/Client.pm',
    ABSTRACT_FROM => 'lib/CrowdSec/Client.pm',
    AUTHOR        => 'Yadd <yadd@>',
    LICENSE       => 'perl',
);
