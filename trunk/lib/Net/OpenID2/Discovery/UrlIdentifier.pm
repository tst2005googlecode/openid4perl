package Net::OpenID2::Discovery::UrlIdentifier;
use base 'Net::OpenID2::Discovery::Identifier';

use warnings;
use strict;
use Carp;
use URI;

# differs from Java API in that the object returned from the constructor
# is normalized.  There is no additional call to make.

sub new {
  my( $class , $identifier ) = @_;
  ref $class  && croak "Can't be called on an instance\n";
  defined $identifier || croak "An identifier must be provided\n";

  # prepend scheme if none present
  $identifier = "http://$identifier" unless( $identifier =~ /^http/i );

  # TODO: does the URI class provide full RFC 3986 normalization?
  return bless( { _identifier => URI->new( $identifier )->canonical } , $class );
}

1;
