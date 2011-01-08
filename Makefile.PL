
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME              => 'Nginx::Engine::Cookies::Resolver',
    VERSION_FROM      => 'lib/Nginx/Engine/Cookies/Resolver.pm', 
    PREREQ_PM         => {
        'Net::DNS' => 0,
        'Nginx::Engine' => 0.04,
    },

    ($] >= 5.005 ?  
      (ABSTRACT_FROM  => 'lib/Nginx/Engine/Cookies/Resolver.pm', 
       AUTHOR         => 'Alexandr Gomoliako <zzz@zzz.org.ua>') : ()),
);



