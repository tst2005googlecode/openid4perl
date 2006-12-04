use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::VerifyRequest;
use Net::OpenID2::Message::ParameterList;
use Net::OpenID2::Message::Parameter;
use Net::OpenID2::Message::AuthSuccess;
use Net::OpenID2::Association::Association;

# test constructor with bad params
eval{ Net::OpenID2::Message::VerifyRequest->new( ) };
like( $EVAL_ERROR , qr/No argument provided/ , 'new(): no arg' );

eval{ Net::OpenID2::Message::VerifyRequest->new( 'foo' ) };
like( $EVAL_ERROR , qr/Invalid argument/ , 'new(): invalid arg' );

# test constructor with a ParameterList parameter
my $param_list = Net::OpenID2::Message::ParameterList->new({one => 1 , two => 2});
my $vr = Net::OpenID2::Message::VerifyRequest->new( $param_list );
isa_ok( $vr , 'Net::OpenID2::Message::VerifyRequest' );

# test constructor with an AuthSuccess parameter
my $mac_key = '0101010101010101010101010101';
my $expires_in = 60 * 60 * 24 * 7; # 1 week
my $assoc = Net::OpenID2::Association::Association->new( TYPE_HMAC_SHA256 , 'the_handle' , $mac_key , $expires_in );
my $params = { claimed_id => 'the_id' ,
               delegate => 'the_del' ,
               compatibility => 0 ,
               return_to => 'https://example.com/mypage?foo=7' ,
               nonce => '2006-01-01T12:00:00Z' ,
               invalidate_handle => 'the_invo_handle' ,
               assoc => $assoc ,
               sign_list => 'identity,return_to,response_nonce' ,
             };

my $auth_success = Net::OpenID2::Message::AuthSuccess->new( $params );
$vr = Net::OpenID2::Message::VerifyRequest->new( $auth_success );
isa_ok( $vr , 'Net::OpenID2::Message::VerifyRequest' );

# test is_valid()
ok( $vr->is_valid , 'is_valid()' );

# test get_handle();
is( $vr->get_handle , 'the_handle' , 'get_handle()' );

# test get_invalidate_handle()
is( $vr->get_invalidate_handle , 'the_invo_handle' , 'get_invalidate_handle()' );

# test get_signed_text()
ok( $vr->get_signed_text , 'get_signed_text()' );

# test get_sig()
ok( $vr->get_sig , 'get_sig' ) ;

