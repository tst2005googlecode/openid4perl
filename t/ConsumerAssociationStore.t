use warnings;
use strict;
use Test::More qw( no_plan );
use English qw( -no_match_vars );
use Net::OpenID2::Consumer::ConsumerAssociationStore;

# try to instantiate
eval{ Net::OpenID2::Consumer::ConsumerAssociationStore->new };
like( $EVAL_ERROR , qr/Not implemented/ , 'new()' );

# mock object
my $store = bless( {} , 'Net::OpenID2::Consumer::ConsumerAssociationStore' );

# try to save
eval { $store->save };
like( $EVAL_ERROR , qr/Not implemented/ , 'save()' );

# try to load
eval { $store->save };
like( $EVAL_ERROR , qr/Not implemented/ , 'load()' );

# try to save
eval { $store->remove };
like( $EVAL_ERROR , qr/Not implemented/ , 'remove()' );

