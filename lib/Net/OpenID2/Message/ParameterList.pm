package Net::OpenID2::Message::ParameterList;

use warnings;
use strict;
use Carp;
use Net::OpenID2::Message::Parameter;

# list of parameters in an OpenID message

# Signature:
# new()
# new( { k1 => v1 , k2 => v2 , ... }
# new( $param_list_to_be_cloned )

sub new {
  my( $class , $param ) = @_;
  ref $class && croak( "Can't be caled on an instance\n" );

  my $self = bless( { _params => {} } , $class );

  # empty constructor list
  unless( defined $param ){
    return $self;
  }

  # hash ref as constructor param
  if( ref $param eq 'HASH' ){
    while( my( $k,$v ) = each %$param ){
      $self->set( Net::OpenID2::Message::Parameter->new( $k,$v ) );
    }
    return $self;
  }

  # copy constructor
  if( ref $param && $param->isa( 'Net::OpenID2::Message::ParameterList' ) ){
    my $clone = $param;
    return bless( $clone , $class );
  }

  # bad params
  croak( 'Bad constructor param list' );
}

# returns all parameters from this list
sub get_parameters {
  my( $self , $arg ) = @_;
  $self or croak("Instance method\n");
  $arg and croak("No arguments accepted\n");
  return values %{$self->{_params}};
}

# adds all parameters from the passed list to this list
sub add_params {
  my( $self , $param_list ) = @_;
  unless( ref $param_list && $param_list->isa( 'Net::OpenID2::Message::ParameterList' ) ){
    croak( 'Not a valid ParameterList object' );
  }

  $self->set( $_ ) for $param_list->get_parameters;
}

# check if a list contains a parameter with a given key
sub has_parameter {
  my( $self , $key ) = @_;
  defined $key || croak( "Invalid key\n" );
  return exists $self->{_params};
}

# overwrites this object's parameters with parameters from the passed ParameterList
sub copy_of {
  my( $self , $param_list ) = @_;
  defined $param_list || croak( "ParameterList required\n" );
  unless( ref $param_list && $param_list->isa( 'Net::OpenID2::Message::ParameterList' ) ){
    croak( 'Not a valid ParameterList object' );
  }

  my %copied = (%{$param_list->{_params}});
  $self->{_params} = \%copied;
}

# remove parameters with the given name
sub remove_parameters {
  my( $self , $param_name ) = @_;
  defined $param_name or croak ("No paramater name given\n");

  delete $self->{_params}->{$param_name};
}

# get a parameter of a given name
sub get_parameter {
  my( $self , $param_name ) = @_;
  defined $param_name or croak ("No paramater name given\n");

  return $self->{_params}->{$param_name};
}

sub set {
  my( $self , $param ) = @_;
  unless( ref $param && $param->isa( 'Net::OpenID2::Message::Parameter' ) ){
    croak( 'Not a valid Parameter object' );
  }

  $self->{_params}->{$param->get_key} = $param;
}

# get a parameter value by key name.  Must be unique.
sub get_parameter_value {
  my( $self , $param_name ) = @_;
  defined $param_name or croak ("No paramater name given\n");

  my $param = $self->get_parameter( $param_name );
  return $param ? $param->get_value : undef;
}

# create a ParameterList from a query string.
# Static.
sub create_from_query_string {
  ref ( my $query = shift ) and croak( "Static method\n" );
  defined $query or croak( "No query provided\n" );

  my $param_list = Net::OpenID2::Message::ParameterList->new();

  for ( split( /&/ , $query ) ){
    my( $param , $value ) = split /=/;
    unless( defined $param && defined $value ){
      croak( "Parameter '$param' is invalid\n" );
    }

    $param = _url_decode( $param );
    $value = _url_decode( $value );

    $param_list->set( Net::OpenID2::Message::Parameter->new( $param => $value ) );
  }
  return $param_list;
}

# create a ParameterList from a ':' delimited OpenID parameter list
# Static.
sub create_from_key_value_form {
  ref( my $key_val = shift ) and croak( "Static method\n" );
  defined $key_val or croak( "No key/value string provided\n" );

  my $param_list = Net::OpenID2::Message::ParameterList->new();

  for( split( /\n/ , $key_val ) ){
    my( $param , $value ) = split /:/;
    unless( defined $param && defined $value ){
      croak( "Parameter '$param' is invalid\n" );
    }

    $param_list->set( Net::OpenID2::Message::Parameter->new( $param => $value ) );
  }
  return $param_list;
}


# util - URL decode a string
sub _url_decode {
  (my $string = $_[0] ) =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
  return $string;
}


1;
