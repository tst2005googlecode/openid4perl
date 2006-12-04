package Net::OpenID2::Discovery::Identifier;

use warnings;
use strict;
use Carp;

sub new {
  croak __PACKAGE__ . ' is an abstract class.  It cannot be instantiated';
}


# get a canonicalized representation of the id
sub get_identifier {
  my $self = shift or croak "Must be called on an instance\n";
  return $self->{_identifier};
}

1;
