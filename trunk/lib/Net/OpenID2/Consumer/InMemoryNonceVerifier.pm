package Net::OpenID2::Consumer::InMemoryNonceVerifier;

use warnings;
use strict;
use Carp;
use Date::Calc::Object qw( Date_to_Time );
use Net::OpenID2::Util qw( nonce2date );
use base( 'Net::OpenID2::Consumer::NonceVerifier' );

my $self = { _idp_map => {} ,
             _max_age => undef ,
           };

sub new {
  my( $class , $max_age ) = @_;
  defined $max_age || croak( "No maximum age provided\n" );
  bless( $self , $class );
  $self->set_max_age( $max_age );
  return $self;
}


sub set_max_age {
  my( $self , $max_age ) = @_;
  defined $max_age || croak( "No maximum age provided\n" );
  $self->{_max_age} = $max_age;
}

sub get_max_age { return $_[0]->{_max_age} }

sub seen {
  my( $self , $idp_url , $nonce ) = @_;
  $idp_url || croak( "No IDP URL provided\n" );
  $nonce || croak( "No nonce provided\n" );

  my $now = Date::Calc->gmtime;
  $self->remove_aged( $now );

  return $self->INVALID_TIMESTAMP unless my $nonce_date = nonce2date( $nonce );
  return $self->TOO_OLD if $self->is_too_old( $now , $nonce_date ) ;
  return $self->SEEN if exists $self->{_idp_map}->{$idp_url}->{$nonce};

  # the nonce has not been seen before.  Store it.
  $self->{_idp_map}->{$idp_url}->{$nonce} = 1; # value is not unimportant
  return $self->OK
}

sub remove_aged {
  my( $self , $since ) = @_;
  unless( ref $since and $since->isa('Date::Calc')){
    croak( "Invalid time provided\n" );
  }
  my $idp_map = $self->{_idp_map};

  while( my($idp_url,$seen_map) = each %$idp_map ){
    foreach my $nonce ( keys %$seen_map ) {
      my $nonce_date = nonce2date( $nonce );
      if( $self->is_too_old( $since , $nonce_date ) ){
        delete $seen_map->{$nonce};
        delete $idp_map->{$idp_url} unless keys %$seen_map;
      }
    }
  }
}

sub is_too_old {
  my( $self , $now , $nonce ) = @_;
  $now || die("No 'now' time provided\n");
  $nonce || die("No 'nonce' time provided\n");
  my $age = Date_to_Time( $now->datetime ) - Date_to_Time( $nonce->datetime );
  return $age > $self->get_max_age;
}


1;

__END__

=head1 NAME

Net::OpenID2::Consumer::InMemoryNonceVerifier

A nonce verifier with no persistant backing.

=head1 SYNOPSIS

$nv = Net::OpenID2::Consumer::InMemoryNonceVerifier->( 60*60*24*3 ); # 3 days

=head1 METHODS

=head2 new( $max_age )

Creates a new nonce verifier.

=head3 Parameters

=over

=item $max_age

The maximum token age in seconds

=back

=head2 remove_aged( $since )

Removes from the store nonces that are older than $since;

=head3 Parameters

=over

=item $since

A C<Date::Calc::Object>

=back

=head2 is_too_old( $now , $nonce_date )

Returns true if the difference between the two dates is less than the
C<max_time> allowed by this object.

=head3 Parameters

=over

=item $now

A C<Date::Calc::Object> of the current time

=item $nonce_date

A C<Date::Calc::Object> of the date in the nonce

=back

=head1 SEE ALSO

Net::OpenID2::Consumer::NonceVerifier

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
