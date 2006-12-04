package Net::OpenID2::Message::AuthSuccess;

use warnings;
use strict;
use Carp;
use Net::OpenID2::Association::Association;
use Net::OpenID2::Message::ParameterList;
use Net::OpenID2::Message::Parameter;
use Net::OpenID2::Message::MessageExtensionFactory;
use Net::OpenID2::Util qw( nonce2date );

use base('Net::OpenID2::Message::Message');

my @REQUIRED_FIELDS = qw( openid.mode
                          openid.return_to
                          openid.assoc_handle
                          openid.signed
                          openid.sig );

my @OPTIONAL_FIELDS = qw(openid.ns
                         openid.claimed_id
                         openid.identity
                         openid.response_nonce
                         openid.invalidate_handle );


sub new {
  my( $class , $arg ) = @_;
  $arg or croak( "No argument provided\n");
  ref $arg or croak( "Invalid argument\n");
  my $self;

  if( ref $arg eq 'HASH' ){
    $self = Net::OpenID2::Message::Message->new() ;
    bless $self , $class;
  } elsif ( $arg->isa('Net::OpenID2::Message::ParameterList') ){
    $self = Net::OpenID2::Message::Message->new( $arg );
    return bless $self , $class;
  } else {
    croak("Invalid argument\n");
  }

  unless( exists $arg->{claimed_id} &&
          exists $arg->{delegate} &&
          exists $arg->{compatibility} &&
          exists $arg->{return_to} &&
          exists $arg->{nonce} &&
          exists $arg->{invalidate_handle} &&
          exists $arg->{assoc} &&
          exists $arg->{sign_list} ){
    croak("Missing arguments\n");
  }

  unless( $arg->{compatibility} ){
    $self->get_params->set( _new_param_obj( 'openid.ns' , $self->OPENID2_NS) );
    $self->claimed( $arg->{claimed_id} );
  }

  $self->get_params->set( _new_param_obj('openid.mode' , $self->MODE_IDRES) );
  $self->identity( $arg->{delegate} );
  $self->return_to( $arg->{return_to} );
  $self->nonce( $arg->{nonce} );

  if( my $ih = $arg->{invalidate_handle} ){
    $self->invalidate_handle( $ih );
  }

  $self->handle( $arg->{assoc}->get_handle );
  $self->signed( $arg->{sign_list} );
  $self->signature( $arg->{assoc}->sign( $self->get_signed_text ) );

  unless( $self->is_valid ){
    croak('Cannot generate valid authentication request for: ' . $self->www_form_encoding . "\n" );
  };

  return $self;
}

sub get_required_fields { return @REQUIRED_FIELDS };

sub is_version_2 {
  my $self = shift or croak("Instance method\n");
  my $ns_param = $self->get_params->get_parameter('openid.ns');
  if( defined $ns_param && $ns_param->get_value eq $self->OPENID2_NS ){
    return 1;
  }
  return;
}

sub mode {
  my( $self , $mode ) = @_;
  my $param_name = 'openid.mode';

  if( $mode ){
    # setter
    unless(($mode eq $self->MODE_IDRES) or ($mode eq $self->MODE_CANCEL)){
      croak("Unknown attribute mode: $mode\n");
    }
    _set_or_get($param_name , @_ );
  } else {
    # getter
    _set_or_get( $param_name , @_ );
  }
}

sub identity { _set_or_get( 'openid.identity' , @_ ) }

sub claimed { _set_or_get( 'openid.claimed_id' , @_ ) }

sub return_to { _set_or_get( 'openid.return_to' , @_ ) }

sub nonce { _set_or_get( 'openid.response_nonce' , @_ ) }

sub invalidate_handle { _set_or_get( 'openid.invalidate_handle' , @_ ) }

sub handle { _set_or_get( 'openid.assoc_handle' , @_ ) }

sub signature { _set_or_get( 'openid.sig' , @_ ) }

sub signed { _set_or_get( 'openid.signed' , @_ ) }

sub user_setup_url { _set_or_get( 'openid.user_setup_url' , @_ ) }

sub get_signed_text {
  my $self = shift or croak("Instance method\n");
  my $signed_text;
  if( my $signed = _set_or_get('openid.signed' , $self) ){
    # signed list
    foreach my $signed_param (split /,/ , $signed){
      my $value = _set_or_get("openid.$signed_param" , $self);
      $signed_text .= "$signed_param:$value\n";
    }
  } else {
    # sign all
    foreach my $p ( sort $self->get_params->get_parameters ){
      $signed_text .= $p->get_key . ':' . $p->get_value . "\n";
    }
  }

  return $signed_text
}


sub is_valid {
  my $self = shift or croak("Instance method\n");
  my $is_compatible = ! $self->is_version_2;
  return unless( $self->SUPER::is_valid );

  if( $is_compatible && (! _set_or_get('openid.ns' , $self)) ){
    carp("Compatibility mode is on, and no 'openid.ns' defined\n");
    return;
  }

  # return_to, if present, must be a valid URL
  my $url = URI->new( $self->return_to );
  unless( $url->scheme and $url->path ){
    carp('Invalid return_to URL: ' . $url->as_string . "\n" );
    return;
  }

  unless( $self->mode eq $self->MODE_IDRES ){
    carp( sprintf "Mode '%s' isn't '%s'\n" , $self->mode , $self->MODE_IDRES);
    return;
  }

  if ( $is_compatible && (! $self->identity ) ) {
    carp("Compatibility mode is on, and no 'openid.identity' defined\n");
    return;
  }

  # check if 'identity' and 'signed' are optional
  if(! $self->identity ){

    # not optional in v1
    return if $is_compatible;

    my $has_auth_ext = 0;
    foreach my $type_uri( $self->get_extentions ){
      if( Net::OpenID2::Message::MessageExtensionFactory->provides_identifier( $type_uri ) ){
        $has_auth_ext = 1;
        last;
      }
    }

    unless( $has_auth_ext ){
      carp("No extension provides authentication services - message invalid\n");
      return;
    }

    if( $self->claimed ){
      carp("claimed_id may be present if and only if identity is present\n");
      return;
    }
  } elsif( (! $is_compatible) && (! $self->claimed) ){
    return;
  }

  # test if nonce is optional or not
  if( ! $is_compatible ){
    return unless $self->nonce;
    return unless( nonce2date( $self->nonce ) );

  } elsif ( $self->nonce ){
    return;
  }

  # return_to and nonce must be signed if signed-list is used
  my @signed_fields = split /,/ , $self->signed;

  unless( grep{ $_ eq 'return_to' } @signed_fields ){
    carp("No 'return_to' found in the signed fields\n");
    return;
  }

  # either a compatibility mode or a nonce signed;
  unless( $is_compatible xor grep{ $_ eq 'response_nonce' } @signed_fields ){
    carp("Not V2 xor a 'response_nonce' found in the signed fields\n");
    return;
  }

  # if the IdP is making an assertion about an Identifier, the
  # "identity" field MUST be present in the signed list
  if( $self->identity && (! grep {$_ eq 'identity'} @signed_fields) ){
    carp( "Identifer present, but no 'identity' is being signed\n" );
    return;
  }

  return 1;

}


#---------------------------------- utils

# _set_or_get( $param_name , $caller )
# _set_or_get( $param_name , $caller , $value )
#
# getters return the value if present, or undef if not
#
# TODO: revmove this method and change all callers in this class
# to use the _get/set_param convenience methods in the parent
# Message class instead.
sub _set_or_get {
  ref $_[0] && shift; # make available to subclasses

  my( $param , $self , $value ) = @_;

  if( $value ){
    # it's a setter
    $self->get_params->set( _new_param_obj( $param , $value ) );
  } else {
    # it's a getter
    my $param_obj = $self->get_params->get_parameter( $param );
    return defined $param_obj ? $param_obj->get_value : undef;
  }
}

# params: $key => $value
sub _new_param_obj {
  return Net::OpenID2::Message::Parameter->new( @_ );
}

1;

__END__

=head1 NAME

Net::OpenID2::Message::AuthSuccess

=head1 SYNOPSIS

Module description

=head1 CONSTANTS

=over

=item VAR_NAME

The description

=back

=head1 METHODS

=head2 method_name( $foo , $bar )

The description

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
