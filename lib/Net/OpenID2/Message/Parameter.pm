package Net::OpenID2::Message::Parameter;
use Carp;

# a key/value pair in an OpenID message

sub new {
  my( $class , $key , $value ) = @_;
  ref $class && croak( "Can't be called on an instance\n" );
  unless( defined $key && defined $value){
    croak( "A key/value pair must be provided\n" );
  }

  return bless( { key => $key , value => $value } , $class );
}

sub get_key {
  return $_[0]->{key};
}

sub get_value {
  return $_[0]->{value};
}

1;
