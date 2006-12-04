use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Date::Calc::Object;
use Net::OpenID2::Consumer::InMemoryNonceVerifier;
use Net::OpenID2::Consumer::NonceVerifier;

# test instantiation with no params
eval{ Net::OpenID2::Consumer::InMemoryNonceVerifier->new() };
like( $EVAL_ERROR , qr/No maximum age provided/ , 'new(): no params' );

# test good params
my $max_seconds = 60 * 10; # 10 minutes
my $nv = Net::OpenID2::Consumer::InMemoryNonceVerifier->new( $max_seconds );
isa_ok( $nv , 'Net::OpenID2::Consumer::InMemoryNonceVerifier' );

# test accessor
is( $nv->get_max_age , $max_seconds , 'get/set max_age' );

# test is_too_old
# use nonces of 9 and 11 minutes for testing since threshold is 10min
my $now = Date::Calc->gmtime;
my $nine_min_ago = $now + [0,0,0,0,-9,0];
my $eleven_min_ago = $now + [0,0,0,0,-11,0];

ok( ! $nv->is_too_old( $now , $nine_min_ago )  , 'is_too_old(): under threshold' );
ok(   $nv->is_too_old( $now , $eleven_min_ago ) , 'is_too_old(): over threshold' );

# create some nonces
my $nonce_9_min_old = date2nonce( $nine_min_ago );
my $nonce_11_min_old = date2nonce( $eleven_min_ago );

is( $nv->seen( 'http://example.com' , $nonce_9_min_old ) , $nv->OK , 'seen(): OK' );
is( $nv->seen( 'http://foo.com'     , $nonce_9_min_old ) , $nv->OK , 'seen(): OK - under different URL' );
is( $nv->seen( 'http://example.com' , $nonce_9_min_old ) , $nv->SEEN , 'seen(): SEEN' );
is( $nv->seen( 'http://example.com' , $nonce_11_min_old ) , $nv->TOO_OLD , 'seen(): TOO_OLD' );
is( $nv->seen( 'http://example.com' , 'bad nonce' ) , $nv->INVALID_TIMESTAMP , 'seen(): INVALID_TIMESTAMP' );

# force injection of an expired timestamp to test remove_aged()
$nv->{_idp_map}->{'http://bar.com'}->{$nonce_11_min_old} = 1;
$nv->remove_aged( $now );
ok( ! exists $nv->{_idp_map}->{'http://bar.com'} , 'remove_aged()' );




sub date2nonce {
  my $date = shift;
  return sprintf("%d-%02d-%02dT%02d:%02d:%02dZ" ,
                 $date->year ,
                 $date->month ,
                 $date->day ,
                 $date->hours ,
                 $date->minutes ,
                 $date->seconds );
}
