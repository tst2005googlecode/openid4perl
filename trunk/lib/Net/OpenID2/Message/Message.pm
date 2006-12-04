package Net::OpenID2::Message::Message;

use warnings;
use strict;
use Carp;
use Net::OpenID2::Message::ParameterList;
use Net::OpenID2::Message::Parameter;
use Net::OpenID2::Message::MessageExtensionFactory;
use URI::URL;


use constant MODE_IDRES  => 'id_res';
use constant MODE_CANCEL => 'cancel';
use constant OPENID2_NS  => 'http://openid.net/signon/2.0';

sub new {
  my( $class , $parameter_list ) = @_;
  if( defined $parameter_list ){
    unless( ref $parameter_list and $parameter_list->isa('Net::OpenID2::Message::ParameterList' ) ){
      croak("Invalid parameter list\n" );
    }
  }

  my $self = { _params      => undef ,
               _ext_counter => undef ,
               _ext_aliases => {} ,
             };
  bless $self , $class;

  if( $parameter_list ){
    $self->_params( $parameter_list );

    foreach my $parameter( $parameter_list->get_parameters ){
      # build the extension list
      my $key = $parameter->get_key;
      if( $key =~ /^openid\.ns\.(.*)/ ){
        $self->{_ext_aliases}->{$parameter->get_value} = $1;
      }
      $self->_ext_counter( scalar keys %{$self->_ext_aliases} );

      unless( $self->is_valid ){
        croak("Invalid set of parameters for the requested message type\n");
      }
    }
  } else {
    $self->_params( new Net::OpenID2::Message::ParameterList );
    $self->_ext_counter( 0 );
    $self->_ext_aliases( {} );
  }
  return $self;
}

sub is_valid {
  (my $self = shift) or croak( "Instance method\n" );
  my @required_fields = $self->get_required_fields;

  foreach my $required ( @required_fields ){
    unless( $self->_params->has_parameter( $required )){
      warn "Required field '$required' is missing\n";
      return;
    }
  }

  return 1;
}

sub get_params {
  # an alias to maintain Java API
  (my $self = shift ) or croak("Instance method\n");
  return $self->_params;
}

sub get_required_fields {
  # sub-classes should exted this
  return ();
}

sub get_parameter_map {
  (my $self = shift) or croak("Instance method\n");
  return { map{ $_->get_key , $_->get_value } $self->_params->get_parameters };
}

sub key_value_form_encoding {
  my $self = shift or croak("Instance method\n");
  my $params_as_string = '';

  foreach my $parameter ($self->_params->get_parameters){
    my $key = $parameter->get_key;
    my $value = $parameter->get_value;
    $params_as_string .= "${key}:${value}\n";
  }

  return $params_as_string;
}

sub www_form_encoding {
  my $self = shift or croak("Instance method\n");
  my $query = join( '&' , map { $_->get_key . '=' . $_->get_value } $self->_params->get_parameters );
  return URI::URL->new( $query )->as_string;
}


# ----------------  extentions implementations below

sub get_extention_alias {
  my( $self , $ext_type_uri ) = @_;
  my $ext_alias = $self->_ext_aliases->{$ext_type_uri};
  unless( $ext_alias ){
    my $count = $self->_ext_counter;
    $self->_ext_counter( ++$count );
    $ext_alias = "ext$count";
    $self->_ext_aliases->{$ext_type_uri} = $ext_alias;
  }
  return $ext_alias;
}

sub get_extentions {
  my $self = shift or croak("Instance method\n");
  return keys %{$self->_ext_aliases};
}

sub add_extention_params {
  my( $self , $extention ) = @_;
  unless( ref $extention && $extention->isa('Net::OpenID2::Message::MessageExtension') ){
    croak("No extention provided\n");
  }

  my $type_uri = $extention->get_type_uri;
  my $alias = $self->get_extention_alias( $type_uri );

  $self->_params->set( Net::OpenID2::Message::Parameter->new( "openid.ns.$alias" , $type_uri ) );

  foreach my $parameter ( $extention->get_parameters->get_parameters ){
    my $key = $parameter->get_key;
    my $param_name = "openid.$alias";
    $param_name .= ".$key" if $key;
    $self->_params->set( new Net::OpenID2::Message::Parameter( $param_name , $parameter->get_value ) );
  }
}

sub get_extention_params {
  my( $self , $ext_type_uri ) = @_;
  $ext_type_uri || croak("No extention type URI provided\n");

  my $ext_list = new Net::OpenID2::Message::ParameterList;
  my $ext_alias = $self->get_extention_alias( $ext_type_uri );

  return $ext_list unless $ext_alias;

  foreach my $parameter ($self->_params->get_parameters){
    my $param_name;
    my $key = $parameter->get_key;

    if( $key =~ /^openid\.$ext_alias\.(.*)/ ){
      $param_name = $1;
    }

    if( $key eq "openid.$ext_alias" ){
      $param_name = '';
    }

    defined $param_name && $ext_list->set( Net::OpenID2::Message::Parameter->new
                                           ( $param_name , $parameter->get_value ) );
  }

  return $ext_list;
}

sub get_extension {
  my( $self , $type_uri ) = @_;
  $type_uri || croak("No type URI provided\n");

  my $extension;

  if( Net::OpenID2::Message::MessageExtensionFactory->has_extension( $type_uri )){
    $extension = Net::OpenID2::Message::MessageExtensionFactory->get_extention( $type_uri );
    $extension->set_parameters( $self->get_extention_params( $type_uri ) );
  }

  return $extension;
}


# -------------- utils below

sub _params {
  my( $self , $arg ) = @_;
  $self->{_params} = $arg if defined $arg;
  return $self->{_params};
}

sub _ext_counter {
  my( $self , $arg ) = @_;
  $self->{_ext_counter} = $arg if defined $arg;
  return $self->{_ext_counter};
}

sub _ext_aliases {
  my( $self , $arg ) = @_;
  $self->{_ext_aliases} = $arg if defined $arg;
  return $self->{_ext_aliases};
}


# convenience methods for getting/setting Parameter object values
sub _set_or_get_param_value {
  my( $self , $param_name , $param_value ) = @_;
  defined $self or die("Instance method\n");
  defined $param_name or die("No param name given\n");

  if ( defined $param_value ) {
    # it's a setter
    $self->get_params->set( Net::OpenID2::Message::Parameter->new( $param_name , $param_value ));
  } else {
    # it's a getter
    my $param_obj = $self->get_params->get_parameter( $param_name );
    return defined $param_obj ? $param_obj->get_value : undef;
  }
}

sub _set_param_value { _set_or_get_param_value( @_ ) };

sub _get_param_value { _set_or_get_param_value( @_ ) };

# convenience methods for creating new Parameter objects
# params: $key => $value
sub _new_param_obj {
  my $self = shift;
  return Net::OpenID2::Message::Parameter->new( @_ );
}


1;

__END__

=head1 NAME

Net::OpenID2::Message::Message

=head1 SYNOPSIS

Module description

=head1 CONSTANTS

=over

=item MODE_IDRES

=item MODE_CANCEL

=item OPENID2_NS

=back

=head1 METHODS

=head2 get_parameter_map()

Combine the key/value pair of each Parameter object in the
ParameterList into a single hash.  Returns a hash reference.

=head2 get_extention_alias( $ext_type_uri )

Retrieves or generates the extension alias for the protocol extension
specified by the given URI string.

If the message doesn't contain already any parameters for the specified
extension, a new extension alias will be generated, making sure it will
not conflict with other existing extensions used in the message.

=head3 Parameters

=over

=item  $ext_type_uri

The URI that identifies the extension

=back

=head3 Returns

The extension alias associated with the extension specifid by the Type URI.

=head2 get_extentions()

Gets a set of extension Type URIs that are present in the message.

=head2 add_extention_params( $extention );

Adds a set of extension-specific parameters to a message.

The parameter names must NOT contain the "openid.<extension_alias>"
prefix. It will be generated dynamically, ensuring there are no conflicts
between extensions.

=head3 Parameters

=over

=item $extension

A L<Net::OpenID2::Message::MessageExtension> containing parameters to be added
to the message.

=back

=head2 get_extention_params( $ext_type_uri )

Retrieves the parameters associated with a protocol extension,
specified by the given Type URI string.

The "openid.ns.<alias>" parameter is included in the returned list.

C<$ext_type_uri> is a string containing the Type URI that identifies
the extension.

=head3 Returns

A L<Net::OpenID2::Message::ParameterList> with all parameters associated
with the specified extension.

=head2 get_extension( $type_uri )

Gets a L<Net::OpenID2::Message::MessageExtension> for the specified Type URI.

=head3 Parameters

=over

=item $type_uri

A string that identifies an extension.

=back

=head3 Returns

An instance of L<Net::OpenID2::Message::MessageExtension> if an implementation
is available, undef otherwise.

The returned object will contain the parameters from the message
belonging to the specified extension.

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
