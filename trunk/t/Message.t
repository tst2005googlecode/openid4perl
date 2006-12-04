use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::Message;
use Net::OpenID2::Message::ParameterList;
use Net::OpenID2::Message::Parameter;
use Net::OpenID2::Message::AX::FetchRequest;

# test new() with invaled param list
eval{ Net::OpenID2::Message::Message->new( bless {} , 'Foo::Bar' ) };
like( $EVAL_ERROR , qr/Invalid parameter list/ , 'new(): bad parameter list' );

# test new with no params
my $msg = Net::OpenID2::Message::Message->new;
isa_ok( $msg , 'Net::OpenID2::Message::Message' , 'new(): no params' );
ok( $msg->_params->isa('Net::OpenID2::Message::ParameterList') , '_params()');
is( $msg->_ext_counter , 0 , '_ext_counter()' );
is( keys %{$msg->_ext_aliases} , 0 , '_ext_aliases()' );

# test instantiation with an instance of ParameterList
my $map = { one => 1 , 'openid.ns.foo' => 'bar' , currency => '$' };
my $param_list = new Net::OpenID2::Message::ParameterList( $map );

# test that the object was properly populated with the ParameterList
$msg = Net::OpenID2::Message::Message->new( $param_list );
isa_ok( $msg , 'Net::OpenID2::Message::Message' , 'new(): param list' );
is( $msg->_params , $param_list , 'new(): Parameterlist arg' );
is( $msg->_ext_aliases->{bar} , 'foo' , 'new(): Parameterlist arg' );
is( $msg->_ext_counter , 1 , 'new(): Parameterlist arg' );

# test get_parameter_map()
is_deeply( $msg->get_parameter_map , $map , 'get_parameter_map()' );

# test key_value_form_encoding()
# since the parameters are stored in a map, the order of params in the
# encoded string probably won't match the insertion order.  So to test,
# load both into a map of "$key:$value" => 1 and test with 'is_deeply'.
my %orig;
while( my($k,$v) = each %$map ){ $orig{"$k:$v"} = 1 }
my %encoded = map{ $_ => 1 } split "\n" , $msg->key_value_form_encoding;
is_deeply( \%encoded , \%orig , 'key_value_form_encoding()' );

# test www_form_encoding()
# use same test approach as above
%orig = ();
while( my($k,$v) = each %$map ){ $orig{"$k=$v"} = 1 };
%encoded = map{ $_ => 1 } split '&' , $msg->www_form_encoding;
is_deeply( \%encoded , \%orig , 'www_form_encoding()' );

# test get_extention_alias()
is( $msg->get_extention_alias('bar') , 'foo' , 'get_extention_alias(): alias exists' );
my $expected_count = $msg->_ext_counter + 1;
is( $msg->get_extention_alias('nonexisting') ,
    "ext$expected_count" ,
    'get_extention_alias(): alias does not exist' );

# test get_extentions()
{
my $got = { map{ $_ , 1 } $msg->get_extentions };
my $expected = { 'bar' => 1 , 'nonexisting' => 1 };
is_deeply( $got , $expected , 'get_extentions()' );
}

# test add_extention_params()
TODO: {
  local $TODO = 'No MessageExtentions implemented yet';
  eval{ $msg->add_extention_params( Net::OpenID2::Message::AX::FetchRequest->new ) };
  ok( ! $EVAL_ERROR  , 'add_extention_params()' );
}


# test get_extention_params()
my $params = $msg->get_extention_params('nosuch');
isa_ok( $params , 'Net::OpenID2::Message::ParameterList' );
ok( ! $params->get_parameters , 'get_extention_params(): non-existing URI' );

TODO:{
  local $TODO = 'Coming Soon';
  $params = $msg->get_extention_params('REPLACE_WITH_A_URI_THAT_EXISTS');
  ok( $params->get_parameters , 'get_extention_params(): existing URI' );
}

# test get_extension()
my $type_uri = 'blah';
TODO:{
  local $TODO = 'Factory not implemented yet';
eval {
is( $msg->get_extension( $type_uri ) , undef , 'get_extenson(): non-existant type' );
};
fail();
}

