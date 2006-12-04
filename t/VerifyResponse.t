use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::VerifyResponse;

# test new with bad arg
eval{ Net::OpenID2::Message::VerifyResponse->new('foo') };
like( $EVAL_ERROR , qr/Invalid parameter/ , 'new(): bad arg' );

# test no-arg constructor
my $vr = Net::OpenID2::Message::VerifyResponse->new();
isa_ok( $vr , 'Net::OpenID2::Message::VerifyResponse' );

my $param_list = Net::OpenID2::Message::ParameterList->new( {} );
$vr = Net::OpenID2::Message::VerifyResponse->new( $param_list );
isa_ok( $vr , 'Net::OpenID2::Message::VerifyResponse' );

# test set/is signature_verified()

for( 0 , 1 ){
  $vr->set_signature_verified( $_ );
  if( $_ ){
    ok( $vr->is_signature_verified , 'set/is signature_verified( 1 )' );
  } else {
    ok(!$vr->is_signature_verified , 'set/is signature_verified( 0 )' );
  }
}


