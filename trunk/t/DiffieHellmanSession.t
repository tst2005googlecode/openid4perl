use warnings;
use strict;

use Test::More qw( no_plan );
use MIME::Base64 qw( encode_base64 decode_base64 );
use Net::OpenID2::Association::DiffieHellmanSession;
use Net::OpenID2::Association::AssociationSessionType qw( DH_SHA256 );
use Net::OpenID2::Association::Association qw( generate_mac_sha256_key );

use English qw( -no_match_vars );

# test create() with a bad type
my $type = bless( {} , 'Foo::Bar' );
eval{
  my $dh = Net::OpenID2::Association::DiffieHellmanSession->create( $type );
};
like( $EVAL_ERROR , qr/Invalid type object/ , 'create(): bad $type param' );

# and now a good type
$type = Net::OpenID2::Association::AssociationSessionType->create( DH_SHA256 );

# create an IDP and RP using defaults
my $idp = Net::OpenID2::Association::DiffieHellmanSession->create( $type );
my $rp = Net::OpenID2::Association::DiffieHellmanSession->create( $type );

# check capabilies
ok( $idp->is_dh_supported , 'is_dh_supported()' );
ok( $idp->is_dh_sha256_supported , 'is_dh_sha256_supported()' );
ok(!$idp->is_dh_sha1_supported , 'is_dh_sha1_supported()' );

# round-trip encode/decode a MAC
my $mac_key = encode_base64( generate_mac_sha256_key );
my $enc_mac_key = $idp->encrypt_mac_key( $mac_key , $rp->public_key_to_string );
my $dec_mac_key = $rp->decrypt_mac_key( $enc_mac_key , $idp->public_key_to_string );
is( $mac_key , $dec_mac_key , 'Round-trip encrypt/decrypt' );


# TODO: test using values in the Java test suite
# my $dh_modulus="ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr";
# my $dh_gen="Ag==";
# my $dh_consumer_public="AL8SSPKap+y4nAhDC5LrkRxuU/Fd6CtWnZ4xnIDnc9XfpbLH8i1ZONIld4VAZAxts+5Ij3mq1CYMGosC5BS1ooLdFj3yNGF2jkRS3WgNLgDMvlNnOfzjRbg3BcdAsJYlVuQz8FjlwQ8WYrzUPfyzcK7X7wLyVSS5nd7XCfKjIZGV";
# my $dh_consumer_private="aPBA0T12u08cSahfgPhX0FMRd3DhU8N1y1lZSYapCmQEN7jac7HrsbqEHiKoyw/ndQz3myJ+jASJ/6Ve267hazLFbeDvY34p6uwkW/xypVS8cG9WWbhsLJrtDjyOfURf7l+OyFcu+C+71jAfA5txnpKV+olMsQqqHnfygnhxrQQ=";
# my $dh_server_public="daimW/oNGmkDIrGmy/1SSE3ECuDH5uLtn6BjVNboacDBpyLx0Hda4P6K6xN7sPJrMOJ4aUai2dSuRlleSN0VcZaaH+z02rhUpBiC8q6OFcBQcJnbo1yOjiFoNI+bMw81YlDOLQ+cpFxiFnH+HgQ1diL4YCC2Dg2mtkQiiQzijcE=";
# my $dh_server_private="S0HBnYYGtByhSTgM6UBcRikfucZih5X7+4AER7Sv2gTQm6FYRmN5wVshoDR1R6jQ42yWZ/LVe4hp1oOfYuoyohzpWTCMTwSif5+IKxJ+KHFQ36ZVWwRBGcGdJFhIPXY1/DkqFl6lm/E0Iv982m9j2gMOmxXhX0h6UwS4n5t93AA=";
# my $mac_key="6zvrrVkA4crhXE+VBNk0V1TfC/Q=";
# my $enc_mac_key="RzOO/T1nO4B5GidVK9scjBeKXSQ=";
