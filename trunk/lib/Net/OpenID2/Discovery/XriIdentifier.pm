package Net::OpenID2::Discovery::XriIdentifier;
use base 'Net::OpenID2::Discovery::Identifier';

use warnings;
use strict;
use Carp;

sub new {
  my( $class , $identifier ) = @_;
  ref $class  && croak "Can't be called on an instance\n";
  defined $identifier || croak "An identifier must be provided\n";

  return bless( { _identifier => $identifier } , $class );

}

1;
