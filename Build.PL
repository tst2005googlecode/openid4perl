use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
                                 module_name         => 'Net::OpenID2',
                                 license             => 'open_source',
                                 dist_author         => 'David Huska <huska [at] sxip [dot] com>',
                                 dist_version_from   => 'VERSION',
                                 build_requires => {
                                                    'Test::More' => 0 ,
                                                    'Crypt::DH' => 0 ,
                                                    'Date::Calc::Object' => 0 ,
                                                    'Digest::SHA' => 0 ,
                                                    'LWP::UserAgent' => 0 ,
                                                    'MIME::Base64' => 0 ,
                                                    'Math::BigInt' => 0 ,
                                                    'Net::Yadis' => 0 ,
                                                    'URI::URL' => 0 ,
                                                    'XML::XPath' => 0 ,
                                                    'Crypt::Random' => 0 ,
                                                   },
                                 add_to_cleanup      => [ 'Net::OpenID-*' ],
);

$builder->create_build_script();
