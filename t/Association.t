use warnings;
use strict;

use Test::More qw( no_plan );
use Net::OpenID2::Association::Association;
use Date::Calc::Object;
use English qw( -no_match_vars );
use Math::BigInt;

# new()
my $delta = 1;
my $type = 'type';
my $handle = 'handle';
my $mac = '0101010101101010101010';

# test missing type
eval{
  my $a =  Net::OpenID2::Association::Association->new( undef , $handle , $mac , $delta );
};
like( $EVAL_ERROR , qr/No type provided/ );

# test missing handle
eval{
  my $a =  Net::OpenID2::Association::Association->new( $type , undef , $mac , $delta );
};
like( $EVAL_ERROR , qr/No handle provided/ );

# test missing MAC
eval{
  my $a =  Net::OpenID2::Association::Association->new( $type , $handle , undef , $delta  );
};
like( $EVAL_ERROR , qr/No MAC key provided/ );

# test invalid date
eval{
  my $a =  Net::OpenID2::Association::Association->new( $type , $handle , $mac , 'today' );
};
like( $EVAL_ERROR , qr/Expiry is invalid/ );

# new() using an absolute date
my $now = Date::Calc->now();
my $a = Net::OpenID2::Association::Association->new( $type , $handle , $mac , $now );
isa_ok( $a , 'Net::OpenID2::Association::Association' );

# test accessors
is( $a->get_type , $type , 'get_type()' );
is( $a->get_handle , $handle , 'get_handle()' );
is( $a->get_mac_key , $mac , 'get_mac_key()' );
is( $a->get_expiry , $now , 'get_expiry()' );

# new() using a seconds delta
$a = Net::OpenID2::Association::Association->new( $type , $handle , $mac , $delta );
isa_ok( $a , 'Net::OpenID2::Association::Association' );
ok( ! $a->has_expired , 'has_expired(): before expiry' );
print "Letting token expire...\n";sleep( $delta + 1 );
ok( $a->has_expired , 'has_expired(): after expiry' );

# create_hmac_sha1()
$a = Net::OpenID2::Association::Association->create_hmac_sha1( $handle , $mac , $delta );
isa_ok( $a , 'Net::OpenID2::Association::Association' );
is( $a->get_type , TYPE_HMAC_SHA1 , 'create_hmac_sha1()' );

# create_hmac_sha256()
$a = Net::OpenID2::Association::Association->create_hmac_sha256( $handle , $mac , $delta );
isa_ok( $a , 'Net::OpenID2::Association::Association' );
is( $a->get_type , TYPE_HMAC_SHA256 , 'create_hmac_sha256()' );

# generate_mac_key()
eval{
  Net::OpenID2::Association::Association::generate_mac_key( 'foo_algorithm' );
};
like( $EVAL_ERROR , qr/Invalid algorithm/ , 'generate_mac_key(): invalid algorithm' );

# generate_hmac_sha1()
$a = Net::OpenID2::Association::Association->generate_hmac_sha1( $handle , $delta );
isa_ok( $a , 'Net::OpenID2::Association::Association' );
is( $a->get_type , TYPE_HMAC_SHA1 , 'generate_hmac_sha1(): type' );
my $bin = Math::BigInt->new( $a->get_mac_key )->as_bin;
$bin = substr( $bin , 2 ); # remove leading '0b'
is( length $bin , HMAC_SHA1_KEYSIZE , 'generate_hmac_sha1(): MAC key' );

# generate_hmac_sha256()
$a = Net::OpenID2::Association::Association->generate_hmac_sha256( $handle , $delta );
isa_ok( $a , 'Net::OpenID2::Association::Association' );
is( $a->get_type , TYPE_HMAC_SHA256 , 'generate_hmac_sha256(): type' );
$bin = Math::BigInt->new( $a->get_mac_key )->as_bin;
$bin = substr( $bin , 2 ); # remove leading '0b'
is( length $bin , HMAC_SHA256_KEYSIZE , 'generate_hmac_sha256(): MAC key' );

# get_failed_association()
$a = Net::OpenID2::Association::Association->get_failed_association( 2 );
isa_ok( $a , 'Net::OpenID2::Association::Association' , 'get_failed_association()' );

# sign/verify setup
my $signer = Net::OpenID2::Association::Association->generate_hmac_sha256( 'test_association' , 60 );
my $verifier = Net::OpenID2::Association::Association->create_hmac_sha256( $signer->get_handle ,
                                                                          $signer->get_mac_key ,
                                                                          $signer->get_expiry );

my $cleartext = "openid.key1:value 1\nopenid.keynumber2:value_2\nfoo:bar";
ok( my $signed = $signer->sign( $cleartext ) , 'sign()' );
ok( $verifier->verify_signature( $cleartext , $signed ) , 'verify_signature(): good signature' )
 or diag( "Signed text was $signed" );

# break the signature
$cleartext .= ':)';
ok( ! $verifier->verify_signature( $cleartext , $signed ) , 'verify_signature(): tampered' )
  or diag( "Signed text was $signed" );
