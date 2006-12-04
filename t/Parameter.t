use warnings;
use strict;

use Test::More tests => 6;
use Net::OpenID2::Message::Parameter;
use English qw( -no_match_vars );

# bad constructor params
my $constructor_msg = 'key/value pair must be provided';
my $key = 'thekey';
my $value = 'thevalue';

eval{ Net::OpenID2::Message::Parameter->new() };
like( $EVAL_ERROR , qr{$constructor_msg} , 'new(): No params' );

eval{ Net::OpenID2::Message::Parameter->new( $key , undef ) };
like( $EVAL_ERROR , qr{$constructor_msg} , 'new(): No value' );

eval{ Net::OpenID2::Message::Parameter->new( undef , $value ) };
like( $EVAL_ERROR , qr{$constructor_msg} , 'new(): No key' );

my $param = Net::OpenID2::Message::Parameter->new( $key , $value );
isa_ok( $param , 'Net::OpenID2::Message::Parameter' , 'new(): Good params' );

# test accessors
is( $param->get_key   , $key   , 'get_key()'   );
is( $param->get_value , $value , 'get_value()' );

