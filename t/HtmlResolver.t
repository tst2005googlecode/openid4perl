use Test::More qw( no_plan );
use Net::OpenID2::Discovery::HtmlResolver;
use Net::OpenID2::Discovery::Discovery;
use HTTP::Response;
use English ( -no_match_vars );
use warnings;
use strict;

# test accessors
my $hr = Net::OpenID2::Discovery::HtmlResolver->new();
is( $hr->conn_timeout  , 3       , 'conn_timeout()' );
is( $hr->max_html_size , 100_000 , 'max_html_size()' );
is( $hr->max_redirects , 10      , 'max_redirects()' );
is( $hr->conn_timeout( 100 )  , 100 , 'conn_timeout( $arg )' );
is( $hr->max_html_size( 2 )   , 2   , 'max_html_size( $arg )' );
is( $hr->max_redirects( 20 )  , 20  , 'max_redirects( $arg )' );

$hr = Net::OpenID2::Discovery::HtmlResolver->new(); # reset
#TODO: my site.  Replace this with a reference implementation or better, a file
#      served locally.
my $identifier = Net::OpenID2::Discovery::Discovery->parse_identifier( 'http://davidhuska.com' );
my $info = $hr->discover( $identifier  );
isa_ok( $info , 'Net::OpenID2::Discovery::DiscoveryInformation' );


