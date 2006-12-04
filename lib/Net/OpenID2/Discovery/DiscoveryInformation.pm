package Net::OpenID2::Discovery::DiscoveryInformation;

use warnings;
use strict;
use Carp;
use base 'Exporter';

use constant OPENID_1_0 => 'http://openid.net/signon/1.0';
use constant OPENID_1_1 => 'http://openid.net/signon/1.1';
use constant OPENID_2_0 => 'http://openid.net/signon/2.0';
use constant IDENTIFIER_SELECT => 'http://openid.net/identifier_select/2.0';
our @EXPORT_OK = qw( OPENID_1_0 OPENID_2_0 IDENTIFIER_SELECT);


# new( \%args )
# args:
# idp_endpoint (required)
# claimed_identifier
# delegate_identifier
# version

sub new {
  my( $class , $args ) = @_;
  my $self = bless( {} , $class );
  if( my $i = $args->{idp_endpoint} ){
    $self->{_idp_endpoint} = $i;
  } else {
    croak "No IDP endpoint specified\n";
  }

  if( my $c = $args->{claimed_identifier} ){
    unless( ref $c and $c->isa( 'Net::OpenID2::Discovery::Identifier' ) ){
      croak( "Provided claimed identifier is invalid\n" );
    }
    $self->{_claimed_identifier} = $c;
  }

  if( my $d = $args->{delegate_identifier} ){
    unless( ref $d and $d->isa( 'Net::OpenID2::Discovery::Identifier' ) ){
      croak( "Provided delegate identifier is invalid\n" );
    }
    $self->{_delegate_identifier} = $d;
  }

  if( my $v = $args->{version} ){
    $self->{_version} = $v;
  } else {
    $self->{_version} = OPENID_2_0;
  }

  return $self;
}

sub get_claimed_identifier { return $_[0]->{_claimed_identifier} }

sub get_delegate_identifier { return $_[0]->{_delegate_identifier} }

sub get_idp_endpoint { return $_[0]->{_idp_endpoint} }

sub get_version { return $_[0]->{_version} }

sub is_version_2 { return $_[0]->get_version eq OPENID_2_0 }

sub has_claimed_identifier { return defined $_[0]->get_claimed_identifier }

sub has_delegate_identifier { return defined $_[0]->get_delegate_identifier }

sub set_version {
  my( $self , $version ) = @_;
  $version || croak "No version specified\n";
  $self->{_version} = $version;
}


1;
