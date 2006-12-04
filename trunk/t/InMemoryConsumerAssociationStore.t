use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Consumer::InMemoryConsumerAssociationStore;

# test constructor
my $store = Net::OpenID2::Consumer::InMemoryConsumerAssociationStore->new();
isa_ok( $store , 'Net::OpenID2::Consumer::InMemoryConsumerAssociationStore' );

# test save() with missing IDP
eval{ $store->save( undef , {} ) };
like( $EVAL_ERROR , qr/No IDP URL provided/ , 'save(): missing IDP' );

# test save() with missing/invalid association params
for( undef , bless( {}, 'Foo::Bar' )){
  eval{ $store->save( 'foo' , $_ ) };
  like( $EVAL_ERROR , qr/Missing or invalid association/ , 'save(): invalid association');
}

# make a few associations
my $type = 'the type';
my $mac = '01010101010101010101';
my $now = Date::Calc->gmtime;
my $a1 = Net::OpenID2::Association::Association->new( $type , 'h1' , $mac , $now );
my $a2 = Net::OpenID2::Association::Association->new( $type , 'h2' , $mac , $now + [0,0,0,0,0,8] ); # 8 sec from now
my $a3 = Net::OpenID2::Association::Association->new( $type , 'h3' , $mac , $now + [0,0,2,0,0,0] ); # 2 days from now
my $a4 = Net::OpenID2::Association::Association->new( $type , 'h4' , $mac , $now + [0,0,0,0,7,0] ); # 7 min from now
my $a5 = Net::OpenID2::Association::Association->new( $type , 'h5' , $mac , $now + [0,0,0,0,1,0] ); # 1 min from now
my $a6 = Net::OpenID2::Association::Association->new( $type , 'h6' , $mac , $now + [4,0,0,0,0,0] ); # 4 years from now
my $a7 = Net::OpenID2::Association::Association->new( $type , 'h7' , $mac , $now + [0,0,0,0,-9,0] ); # 9 min ago


# test save() with good parameters
my $url1 = 'http://example.com';
my $url2 = 'http://foo.com';

ok( $store->save( $url1 , $a1 ) , 'save():' );
ok( $store->save( $url1 , $a2 ) , 'save():' );
ok( $store->save( $url1 , $a3 ) , 'save():' );
ok( $store->save( $url1 , $a4 ) , 'save():' );
ok( $store->save( $url2 , $a5 ) , 'save():' );
ok( $store->save( $url1 , $a6 ) , 'save():' );
ok( $store->save( $url2 , $a7 ) , 'save():' );

# test load() with missing URL
eval{ $store->load };
like( $EVAL_ERROR , qr/No IDP URL provided/ , 'load(): missing IDP' );

# test load() with both URL and handle params
is( $store->load( $url1 , 'h2' ) , $a2 , 'load( $url , $header )' );
is( $store->load( $url2 , 'h5' ) , $a5 , 'load( $url , $header )' );

# test load() with an unseen URL
is( $store->load( 'http://openid.net' ) , undef , 'load(): unseen IDP' );

# test load() with only a URL
is( $store->load( $url1 ) , $a6 , 'load( $url )' );

# test that expired associations are removed
is( $store->load( $url2 , 'h7' ) , undef , 'load(): expired association' );

# test remove() with missing url
eval{ $store->remove( undef , 'foo' ) };
like( $EVAL_ERROR , qr/No IDP URL provided/ , 'remove(): missing IDP' );

# test remove() with missing handle
eval{ $store->remove( 'foo' , undef ) };
like( $EVAL_ERROR , qr/No handle provided/ , 'remove(): missing handle' );

# test remove() with good params
$store->remove( $url1 , 'h2' );
is( $store->load( $url1 , 'h2' ) , undef , 'remove()' );
