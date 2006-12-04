use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Util qw( nonce2date );

# test nonce2date with no parameter
eval{ nonce2date() };
like( $EVAL_ERROR , qr/No nonce provided/ , 'nonce2date(): missing nonce' );

# test nonce2date with invalid parameter
ok( ! nonce2date('2001-12-30-12-00-00') , 'nonce2date(): invalid nonce' );

# test nonce2date with upper/lower 'T' and 'Z'
my $nonce = '2001-12-30T12:00:00Zrandomstuff';
for( $nonce , lc($nonce) ){
  my $date = nonce2date( $_ );
  ok( (ref $date && $date->isa('Date::Calc')) , 'nonce2date(): Upper/lower "T" "Z"' );
}

# test nonce2date without unique trailing string
$nonce = '2001-12-30T02:45:00Z';
my $date = nonce2date( $nonce );
ok( (ref $date and $date->isa('Date::Calc')) , 'nonce2date(): without unique string' );


# test date components
is( $date->year    , 2001 , 'nonce2date(); year component' );
is( $date->month   , 12   , 'nonce2date(); month component' );
is( $date->day     , 30   , 'nonce2date(); day component' );
is( $date->hours   , '02' , 'nonce2date(); hour component' );
is( $date->minutes , 45   , 'nonce2date(); minute component' );
is( $date->seconds , '00' , 'nonce2date(); second component' );
