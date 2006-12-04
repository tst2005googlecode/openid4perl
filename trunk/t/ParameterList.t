use warnings;
use strict;

use Test::More qw( no_plan );
use Net::OpenID2::Message::ParameterList qw( create_from_query_string );
use Net::OpenID2::Message::Parameter;
use English qw( -no_match_vars );

# bad constructor params

my $constructor_msg = 'Bad constructor param list';
eval{ Net::OpenID2::Message::ParameterList->new( 'somestring' ) };
like( $EVAL_ERROR , qr{$constructor_msg} , 'new(): string' );

eval{ Net::OpenID2::Message::ParameterList->new( qw/one two three/ ) };
like( $EVAL_ERROR , qr{$constructor_msg} , 'new(): array list' );

# good constructor params

# empty param list
my $scratch_list = Net::OpenID2::Message::ParameterList->new();
isa_ok( $scratch_list , 'Net::OpenID2::Message::ParameterList' );

# copy constructor
my $clone_list = Net::OpenID2::Message::ParameterList->new( $scratch_list );
isa_ok( $clone_list , 'Net::OpenID2::Message::ParameterList' );

# hash parameter
my $hash_param_list = Net::OpenID2::Message::ParameterList->new( { one => 1 , two => 2 } );
isa_ok( $hash_param_list , 'Net::OpenID2::Message::ParameterList' );

# test add_params()
eval{ $scratch_list->add_params( 7 ) };
like( $EVAL_ERROR , qr{Not a valid ParameterList object} , 'add_params(): int' );

$scratch_list->add_params( $hash_param_list );
ok( $scratch_list->has_parameter( 'one' ) && $scratch_list->has_parameter( 'two' ) ,
    'add_params(): present keys' );

# test copy_of()
my $empty_list = Net::OpenID2::Message::ParameterList->new();
$empty_list->copy_of( $hash_param_list );
is_deeply( $empty_list->{_params} , $hash_param_list->{_params} , 'copy_of()' );

# test get_parameters( $parameter_name )
$scratch_list->set( Net::OpenID2::Message::Parameter->new( 'foo' => 'stuff' )); # set foo
my @params_of_foo = $scratch_list->get_parameters();
is( @params_of_foo , 3 , 'get_parameters( $param_name )' );

# test get_parameter()
# At this point there should be:
# - one parameter with the key 'one'
# - one parameter with the key 'foo'
# - zero parameters with the key 'zero'

ok( !$scratch_list->get_parameter( 'zero' ) , 'get_parameter() - Non-existent key' );

my $one_param = $scratch_list->get_parameter( 'one' );
isa_ok( $one_param , 'Net::OpenID2::Message::Parameter' , 'get_parameter() - good params' );

# test remove_parameter()
$scratch_list->remove_parameters( 'foo' );
is( $scratch_list->get_parameter( 'foo' ) , undef , 'remove_parameters()' );

# test set()
# a parameter with the key 'one' already exists
eval{ $scratch_list->set( Net::OpenID2::Message::Parameter->new( one => '1' ) ) };
ok(! $EVAL_ERROR , 'set(): Param exists' );

$scratch_list->set( Net::OpenID2::Message::Parameter->new( newbie => 'blip' ) ) ;
ok( $scratch_list->has_parameter( 'newbie' ) , 'set(): New param' );

# test get_parameter_value()
is( $scratch_list->get_parameter_value( 'newbie' ) , 'blip' , 'get_parameter_value()' );

# test create_from_query_string()
my $qstring = 'one=the%20one&two=the%20two&dollar=%24%20sign';
my $list_from_qstring = Net::OpenID2::Message::ParameterList::create_from_query_string( $qstring );
is( $list_from_qstring->get_parameter_value( 'dollar' ) , '$ sign' , 'list_from_qstring()' );

# add bad params
$qstring .= '&bad&good=ok';
eval{
  $list_from_qstring = Net::OpenID2::Message::ParameterList::create_from_query_string( $qstring )
};
like( $EVAL_ERROR , qr/'bad' is invalid/ , 'list_from_qstring(): invalid params' );

# test create_from_key_value_form()
my $key_val = <<EOM;
item1:this is item one
item2:this is something else
number3:last but not least
EOM

my $list_from_key_val = Net::OpenID2::Message::ParameterList::create_from_key_value_form( $key_val );
is( $list_from_key_val->get_parameter_value( 'number3' ) , 'last but not least' , 'list_from_key_val()' );

# add bad params
$key_val .= "junk\ngood:param";
eval{
  $list_from_key_val = Net::OpenID2::Message::ParameterList::create_from_key_value_form( $key_val );
};
like( $EVAL_ERROR , qr/'junk' is invalid/ , 'list_from_key_val(): invalid params' );



