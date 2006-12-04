use warnings;
use strict;

use Test::More qw( no_plan );
use Net::OpenID2::Association::AssociationSessionType qw( NO_ENCRYPTION EMPTY DH_SHA1 DH_SHA256 );
use Net::OpenID2::Association::Association;
use Net::OpenID2::Association::DiffieHellmanSession;
use English qw( -no_match_vars );

# test create()
my $no_enc_sha1mac = Net::OpenID2::Association::AssociationSessionType->create(
  NO_ENCRYPTION ,
  TYPE_HMAC_SHA1 ,
);
isa_ok( $no_enc_sha1mac , 'Net::OpenID2::Association::AssociationSessionType' , 'create(): Right type' );

# test get_association_type()
is( $no_enc_sha1mac->get_association_type , TYPE_HMAC_SHA1 , 'get_association_type()' );

# test get_h_algorithm()
is( $no_enc_sha1mac->get_h_algorithm , undef , 'get_h_algorithm()' );

# test constructors of the remaining types
my $no_enc_sha256mac = Net::OpenID2::Association::AssociationSessionType->create(
   NO_ENCRYPTION ,
   TYPE_HMAC_SHA256 ,
);
isa_ok( $no_enc_sha256mac , 'Net::OpenID2::Association::AssociationSessionType' , 'create(): Right type' );
is( $no_enc_sha256mac->get_association_type , TYPE_HMAC_SHA256 , 'get_association_type()' );
is( $no_enc_sha256mac->get_h_algorithm , undef , 'get_h_algorithm()' );

my $dh_sha1 = Net::OpenID2::Association::AssociationSessionType->create(
   DH_SHA1 ,
   TYPE_HMAC_SHA1 ,
);
isa_ok( $dh_sha1 , 'Net::OpenID2::Association::AssociationSessionType' , 'create(): Right type' );
is( $dh_sha1->get_association_type , TYPE_HMAC_SHA1 , 'get_association_type()' );
is( $dh_sha1->get_h_algorithm , H_ALGORITHM_SHA1 , 'get_h_algorithm()' );

my $dh_sha256 = Net::OpenID2::Association::AssociationSessionType->create(
   DH_SHA256 ,
   H_ALGORITHM_SHA256 ,
);
isa_ok( $dh_sha256 , 'Net::OpenID2::Association::AssociationSessionType' , 'create(): Right type' );
is( $dh_sha256->get_association_type , TYPE_HMAC_SHA256 , 'get_association_type()' );
is( $dh_sha256->get_h_algorithm , H_ALGORITHM_SHA256 , 'get_h_algorithm()' );

my $dh_compat_sha1mac = Net::OpenID2::Association::AssociationSessionType->create(
   EMPTY ,
   TYPE_HMAC_SHA1 ,
);
isa_ok( $dh_compat_sha1mac , 'Net::OpenID2::Association::AssociationSessionType' , 'create(): Right type' );
is( $dh_compat_sha1mac->get_association_type , TYPE_HMAC_SHA1 , 'get_association_type()' );
is( $dh_compat_sha1mac->get_h_algorithm , undef , 'get_h_algorithm()' );


# test is_better()
ok( $no_enc_sha256mac->is_better( $no_enc_sha1mac ) , 'is_better()' );
ok(!$no_enc_sha1mac->is_better( $no_enc_sha256mac ) , 'is_better()' );
