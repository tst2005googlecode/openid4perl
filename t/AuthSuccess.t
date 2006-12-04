use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::AuthSuccess;
use Net::OpenID2::Message::ParameterList;
use Net::OpenID2::Association::Association;

# test new() with bad params
eval{ Net::OpenID2::Message::AuthSuccess->new( ) };
like( $EVAL_ERROR , qr/No argument provided/ , 'new(): no arg' );

eval{ Net::OpenID2::Message::AuthSuccess->new( 'foo' ) };
like( $EVAL_ERROR , qr/Invalid argument/ , 'new(): invalid arg' );

# test new() with good parms
my $param_list = Net::OpenID2::Message::ParameterList->new;
my $as = Net::OpenID2::Message::AuthSuccess->new( $param_list );
isa_ok( $as , 'Net::OpenID2::Message::AuthSuccess' );

#all params but one
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
               };

eval{
  Net::OpenID2::Message::AuthSuccess->new( $params );
};
like( $EVAL_ERROR , qr/Missing arguments/ , 'new(): some missing args' );

# add the missing param
$params->{sign_list} = 'identity,return_to,response_nonce';
$as = Net::OpenID2::Message::AuthSuccess->new( $params );
isa_ok( $as , 'Net::OpenID2::Message::AuthSuccess'  );

# TODO: although most methods of AuthSuccess.pm are exercised by the constructors,
# this class needs more test coverage
