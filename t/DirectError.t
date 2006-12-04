use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::DirectError;

# test new() with no args
eval{ Net::OpenID2::Message::DirectError->new() };
like( $EVAL_ERROR , qr/Invalid argument/ , 'new(): missing param' );

# test new() with ok args
my $de = Net::OpenID2::Message::DirectError->new( 'The error message' );
isa_ok( $de , 'Net::OpenID2::Message::DirectError' );

my $param_list = Net::OpenID2::Message::ParameterList->new( {} );
$de = Net::OpenID2::Message::DirectError->new( $param_list );
isa_ok( $de , 'Net::OpenID2::Message::DirectError' );

# test set_error_msg()
eval{ $de->set_error_msg('foo') };
ok(! $EVAL_ERROR , 'set_error_msg()' );

# test set_contact()
eval{ $de->set_contact('foo') };
ok(! $EVAL_ERROR , 'set_contact()' );

# test set_reference()
eval{ $de->set_reference('foo') };
ok(! $EVAL_ERROR , 'set_reference()' );
