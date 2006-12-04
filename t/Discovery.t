use Test::More qw( no_plan );
use Net::OpenID2::Discovery::Discovery;
use English ( -no_match_vars );

# bad factory params
for( undef , '' ){
  eval{ Net::OpenID2::Discovery::Discovery->parse_identifier };
  like( $EVAL_ERROR , qr/No identifier provided/ , 'create_identifier(): bad params' );
}

# test XRI identification
my $should_create = 'Net::OpenID2::Discovery::XriIdentifier';
check_uri( [qw( xri://foo/bar =foo @acme +alpha $beta )] , $should_create );

# test URL identification
$should_create = 'Net::OpenID2::Discovery::UrlIdentifier';
check_uri( [(qw( http://foo https://foo.html foo/bat/bar ))] , $should_create );

# test scheme prepend
my $url = 'some/bare/string';
my $id = Net::OpenID2::Discovery::Discovery->parse_identifier( $url );
is( $id->get_identifier , "http://$url" , 'get_identifier(): prepend' );

# test normalization
$url = 'HTTPS://path/TO/my ID';
my $normalized = 'https://path/TO/my%20ID';
$id = Net::OpenID2::Discovery::Discovery->parse_identifier( $url );
is( $id->get_identifier , $normalized , 'get_identifier(): normalized' );

# test discover on xri
my $xri = '=huska';
$id = Net::OpenID2::Discovery::Discovery->parse_identifier( $xri );
my @info = Net::OpenID2::Discovery::Discovery->discover( $id );
for( @info ){
  isa_ok( $_ , 'Net::OpenID2::Discovery::DiscoveryInformation' );
}

# test discover on html
$url = 'http://blame.ca';
$id = Net::OpenID2::Discovery::Discovery->parse_identifier( $url );
@info = Net::OpenID2::Discovery::Discovery->discover( $id );
for( @info ){
  isa_ok( $_ , 'Net::OpenID2::Discovery::DiscoveryInformation' );
}



sub check_uri{
  my( $uri , $class ) = @_;
  foreach my $uri( @$uri ){
    my $identifier = Net::OpenID2::Discovery::Discovery->parse_identifier( $uri );
    isa_ok( $identifier , $class , "Identifier instantiation on $uri" );
  }
}
