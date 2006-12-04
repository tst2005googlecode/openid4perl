use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Consumer::NonceVerifier;

# shouldn't be able to instantiate
my $regex = qr/Not implemented/;
eval{ Net::OpenID2::Consumer::NonceVerifier->new };
like( $EVAL_ERROR , $regex , 'new(): abstract class' );


# shouldn't be able to run
my $mock = bless {} , 'Net::OpenID2::Consumer::NonceVerifier';

foreach my $sub qw( seen get_max_age set_max_age ){
  eval{ $mock->$sub };
  like( $EVAL_ERROR , $regex , "$sub(): abstract class" );
}
