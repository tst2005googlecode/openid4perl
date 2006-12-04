use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::MessageExtension;

# no methods should be implemented
my $regex = qr/Not implemented/;
eval{ Net::OpenID2::Message::MessageExtension->new };
like( $EVAL_ERROR , $regex , 'new(): abstract' );

my $mock = bless {} , 'Net::OpenID2::Message::MessageExtension';
foreach my $sub qw( get_type_uri get_parameters set_parameters provides_identifier ){
  eval{ $mock->$sub };
  like( $EVAL_ERROR , $regex , "$sub(): abstract" );
}

