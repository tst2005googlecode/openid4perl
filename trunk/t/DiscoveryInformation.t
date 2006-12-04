use Test::More qw( no_plan );
use Net::OpenID2::Discovery::DiscoveryInformation qw( OPENID_1_0 OPENID_2_0 );
use Net::OpenID2::Discovery::Discovery;
use English ( -no_match_vars );
use warnings;
use strict;

# test missing idp endpoint
eval{
  Net::OpenID2::Discovery::DiscoveryInformation->new();
};
like( $EVAL_ERROR , qr/No IDP endpoint specified/ , 'new(): missing idp endpoint' );

# test with idp endpoint
my $idp = 'http://example.com/idp';
my $args = { idp_endpoint => $idp };
my $info = Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
isa_ok( $info , 'Net::OpenID2::Discovery::DiscoveryInformation' );

# test properties
ok( ! $info->has_claimed_identifier , 'has_claimed_identifier(): before set' );
ok( ! $info->has_delegate_identifier , 'has_delegate_identifier(): before set' );

# test invalid claimed identifier
my $claimed = bless( {} , 'Foo::Bar' );
$args->{ claimed_identifier } = $claimed;
eval{
  Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
};
like( $EVAL_ERROR , qr/Provided claimed identifier is invalid/ , 'new(): invalid claimed identifier' );

# test ok claimed identifier
$claimed = Net::OpenID2::Discovery::Discovery->parse_identifier('http://example.com');
$args->{ claimed_identifier } = $claimed;
$info = Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
isa_ok( $info , 'Net::OpenID2::Discovery::DiscoveryInformation' );

# test invalid delegate identifier
my $delegate = bless( {} , 'Foo::Bar' );
$args->{ delegate_identifier } = $delegate;
eval{
  Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
};
like( $EVAL_ERROR , qr/Provided delegate identifier is invalid/ , 'new(): invalid delegate identifier' );

# test ok delegate identifier
$delegate = Net::OpenID2::Discovery::Discovery->parse_identifier('http://example.com');
$args->{ delegate_identifier } = $delegate;
$info = Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
isa_ok( $info , 'Net::OpenID2::Discovery::DiscoveryInformation' );

# test accessors
is( $info->get_idp_endpoint , $idp , 'get_idp_endpoint()');
is( $info->get_delegate_identifier , $delegate , 'get_delegate_identifier()' );
is( $info->get_claimed_identifier , $claimed , 'get_claimed_identifier()' );
ok( $info->has_claimed_identifier , 'has_claimed_identifier(): after set' );
ok( $info->has_delegate_identifier , 'has_delegate_identifier(): after set' );
ok( $info->is_version_2 , 'is_version_2(): object default' );

$info->set_version( OPENID_1_0 );
is( $info->get_version , OPENID_1_0 , 'get_version():' );
ok( ! $info->is_version_2 , 'is_version_2(): unset' );
