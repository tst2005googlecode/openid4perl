use Test::More qw( no_plan );
use Net::OpenID2::Discovery::Identifier;
use English ( -no_match_vars );

# make sure class won't instatiate
eval{  Net::OpenID2::Discovery::Identifier->new };
like ( $EVAL_ERROR , qr/cannot be instantiated/ , 'Abstract class' );
