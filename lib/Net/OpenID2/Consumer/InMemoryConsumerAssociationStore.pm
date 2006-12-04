package Net::OpenID2::Consumer::InMemoryConsumerAssociationStore;

use warnings;
use strict;
use Carp;

use base( 'Net::OpenID2::Consumer::ConsumerAssociationStore' );
use Net::OpenID2::Association::Association;

sub new{ bless {} , 'Net::OpenID2::Consumer::InMemoryConsumerAssociationStore' };

sub save {
  my( $self , $idp_url , $association ) = @_;
  $idp_url || croak( "No IDP URL provided\n" );
  unless( ref $association and $association->isa( 'Net::OpenID2::Association::Association' )){
    croak( "Missing or invalid association\n" );
  }
  $self->{_idp_map}->{$idp_url}->{$association->get_handle()} = $association;
}

# $handle is optional
sub load {
  my( $self , $idp_url , $handle ) = @_;
  $idp_url || croak( "No IDP URL provided\n" );
  $self->remove_expired;
  my $handle_map = $self->{_idp_map}->{$idp_url};

  # return the association for this handle if we have one
  $handle && return $handle_map->{$handle};

  # otherwise return the association that expires latest
  return( map{ $_->[1] } sort{ $a->[0] cmp $b->[0] } map{ [$_->get_expiry,$_] } values %$handle_map )[-1];
}

sub remove {
  my( $self , $idp_url , $handle ) = @_;
  $idp_url || croak( "No IDP URL provided\n" );
  $handle  || croak( "No handle provided\n" );
  delete $self->{_idp_map}->{$idp_url}->{$handle};
}

sub remove_expired {
  my $self = shift;
  while( my($idp,$handle_map) = each %{$self->{_idp_map}} ){
    while( my($handle,$association) = each %$handle_map ){
      $association->has_expired && $self->remove( $idp , $handle );
    }
  }
}

1;
