use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Message::IndirectError;

my $ie = Net::OpenID2::Message::IndirectError->new('The error string');
isa_ok( $ie , 'Net::OpenID2::Message::IndirectError' );
