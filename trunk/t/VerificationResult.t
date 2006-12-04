use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Consumer::VerificationResult;

# test instantiation
my $vr = new Net::OpenID2::Consumer::VerificationResult;
isa_ok( $vr , 'Net::OpenID2::Consumer::VerificationResult' );

# test set_verified_id() with bad params
my $regex = qr/Provided ID is invalid/;
eval{ $vr->set_verified_id };
like( $EVAL_ERROR , $regex , 'set_verified_id(); missing param' );

eval{ $vr->set_verified_id( bless {} , 'Foo::Bar' ) };
like( $EVAL_ERROR , $regex , 'set_verified_id(); invalid param' );

# test verified_id accessors
my $mock_id = bless {} , 'Net::OpenID2::Discovery::Identifier';
$vr->set_verified_id( $mock_id );
is( $vr->get_verified_id , $mock_id , 'get/set_verified_id()' );

#test set_idp_url with bad params
eval{ $vr->set_idp_url };
like( $EVAL_ERROR , qr/No URL provided/ , 'set_idp_url(): missing params' );

# test idp_url accessors
my $url = 'http://example.com';
$vr->set_idp_url( $url );
is( $vr->get_idp_url , $url , 'get/set_idp_url()' );



