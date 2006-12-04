package Net::OpenID2::Message::AuthRequest;

use warnings;
use strict;
use Carp;
use base('Net::OpenID2::Message::Message');
use Net::OpenID2::Association::Association;
use URI;

use constant MODE_SETUP => 'checkid_setup';
use constant MODE_IMMEDIATE => 'checkid_immediate';
use constant SELECT_ID => 'http://openid.net/identifier_select/2.0';
my @REQUIRED_FIELDS = qw( openid.mode );
my @OPTIONAL_FIELDS = qw( openid.ns
                          openid.claimed_id
                          openid.identity
                          openid.assoc_handle
                          openid.realm
                          openid.trust_root
                          openid.return_to 
                        );


sub new {
  my( $class , $arg ) = @_;

  unless( $arg and ref $arg ){
    croak("No argument provided\n");
  }

  # ParameterList constructor
  if( ref $arg eq 'Net::OpenID2::Message::ParameterList' ){
    my $self = Net::OpenID2::Message::Message->new( $arg );
    return bless( $self , $class );
  }

  # check passed parameters
  exists $arg->{claimed_id} or croak("No 'claimed_id' provided\n");
  exists $arg->{delegate} or croak("No 'delegate' provided\n");
  exists $arg->{compatibility} or croak("No 'compatibility' provided\n");
  exists $arg->{return_to_url} or croak("No 'return_to_url' provided\n");
  exists $arg->{handle} or croak("No 'handle' provided\n");

  # set the 'realm' as the 'return to url' if none provided
  $arg->{realm} ||= $arg->{return_to_url};

  my $self = Net::OpenID2::Message::Message->new();
  bless( $self , $class );

  unless( $arg->{compatibility} ){
    $self->_set_param_value( 'openid.ns' , $self->OPENID2_NS );
    $self->claimed( $arg->{claimed_id} );
  }

  $self->set_identity( $arg->{identity} );

  if( my $r = $arg->{return_to_url} ){
    $self->set_return_to( $r );
  }

  if( my $r = $arg->{realm} ){
    $self->set_realm( $r );
  }

  if( $arg->{handle} eq Net::OpenID2::Association::Association->FAILED_ASSOC_HANDLE ){
    $self->set_handle( $arg->{handle} );
  }

  $self->set_immediate( 0 );

  unless( $self->is_valid ){
    croak("Cannot generate valid authentication request for :" . $self->www_form_encoding . "\n" );
  }

  return $self;
}


sub get_required_fields{ return @REQUIRED_FIELDS }

sub set_op_endpoint {
  my( $self , $url ) = @_;
  unless( ref $url && $url->isa('URI') ){
    croak("Not a valid URI object\n");
  }

  $self->{_op_endpoint} = $url->as_string;
}

sub get_op_endpoint {
  return $_[0]->{_op_endpoint};
}

sub set_immediate {
  my( $self , $immediate ) = @_;
  if( $immediate ){
    $self->_set_param_value( 'openid.mode' , MODE_IMMEDIATE );
  } else {
    $self->_set_param_value( 'openid.mode' , MODE_SETUP );
  }
}

sub is_immediate {
  return $_[0]->_get_param_value('openid.mode') eq MODE_IMMEDIATE;
}

sub is_version_2 {
  my $self = shift;
  if( my $n = $self->_get_param_value('openid.ns')){
    return $n eq $self->OPENID2_NS;
  } else {
    return;
  }
}

sub set_identity {
  my( $self , $identity ) = @_;
  $self->_set_param_value( 'openid.identity' , $identity );
}

sub get_identity {
  return $_[0]->_get_param_value( 'openid.identity' );
}

sub set_claimed {
  my( $self , $claimed ) = @_;
  $self->_set_param_value( 'openid.claimed_id' , $claimed );
}

sub get_claimed {
  return $_[0]->_get_param_value('openid.claimed_id' );
}

sub set_handle {
  my( $self , $handle ) = @_;
  $self->_set_param_value('openid.handle' , $handle );
}

sub get_handle {
  return $_[0]->_get_param_value('openid.handle');
}

sub set_return_to {
  my( $self , $return_to ) = @_;
  $self->_set_param_value( 'openid.return_to' , $return_to );
}

sub get_return_to {
  return $_[0]->_get_param_value( 'openid.return_to' );
}

sub get_return_to_url {
  return URI->new( $_[0]->get_return_to );
}

sub set_realm {
  my( $self , $realm ) = @_;
  my $param = $self->is_version_2 ? 'openid.realm' : 'openid.trust_root';
  $self->_set_param_value( $param , $realm );
}

sub get_realm {
  my $self = shift;
  my $param = $self->is_version_2 ? 'openid.realm' : 'openid.trust_root';
  return $self->_get_param_value( $param );
}

sub is_valid {
  my $self = shift;

  return unless $self->SUPER::is_valid;
  my $compatibility = $self->is_version_2;

  if( $compatibility && $self->_get_param_value('openid.ns') ){
    carp("V2 and openid.ns is set\n");
    return;
  }

  if( $compatibility && ($self->get_identity eq SELECT_ID) ){
    carp("V2 and openid.identity is set\n");
    return;
  }

  if( my $mode = $self->_get_param_value('openid.mode') ){
    unless( $mode eq MODE_SETUP or $mode eq MODE_IMMEDIATE ){
      carp(sprintf "'openid.mode' is neither '%s' or '%s'\n" ,
             MODE_SETUP ,
             MODE_IMMEDIATE );
      return;
    }
  }

  # if present, return_to must be a valid URL
  if( my $url = $self->get_return_to_url ){
    unless( $url->scheme && $url->path ){
      carp("'return_to' URL '$url' is invalid\n");
      return;
    }
  }

  if( $self->get_return_to ){
    if( $compatibility or (! $self->_get_param_value('openid.realm'))){
      carp("'return_to' setting conflicts with V2 or 'openid.realm'\n");
      return;
    }
  }

  if( $compatibility && $self->_get_param_value('openid.realm') ){
    carp( "V2 conflicts with 'openid.realm' setting\n" );
    return;
  }

  if( !$compatibility && $self->_get_param_value('openid.trust_root') ){
    carp("Not V2 but 'openid.trust_root' is set\n");
    return;
  }

  # are 'claimed_id' and 'identity' optional
  if( ! $self->_get_param_value('openid.identity') ){

      # not optional in V1
      return if $compatibility;
      my $has_auth_provider;

      foreach my $extention ($self->get_extentions){
        if( MessageExtensionFactory->provides_identifier( $extention )){
          $has_auth_provider = 1;
          last;
        }
      }

      unless( $has_auth_provider ){
        carp("No auth provider found\n");
        return;
      }

      if( $self->get_claimed ){
        carp("'openid.claimed_id' found\n");
        return;
      }
    } elsif( ! $compatibility && (! $self->get_claimed ) ){
      carp("Not V2 and no 'openid.claimed_id' found\n");
      return;
    }

    if( my $realm = $self->get_realm ){
      my $rv = Net::OpenID2::Server::RealmVerifier->new;
      return $rv->match( $realm , $self->get_return_to ) eq Net::OpenID2::Server::RealmVerifier->OK;
    } else {
      return 1;
    }
}


sub realm_check { croak("NOT IMPLEMENTED YET\n") };
sub remove_wildcard { croak("NOT IMPLEMENTED YET\n") };


1;

__END__

=head1 NAME

Net::OpenID2::Message::AuthRequest

=head1 SYNOPSIS

Module description

=head1 CONSTANTS

=over

=item MODE_SETUP

=item MODE_IMMEDIATE

=item SELECT_ID

=item REQUIRED_FIELDS

=item OPTIONAL_FIELDS

=back

=head1 METHODS

=head2 method_name( $foo , $bar )

The description

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
