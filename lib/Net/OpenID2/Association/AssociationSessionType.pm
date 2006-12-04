package Net::OpenID2::Association::AssociationSessionType;

use warnings;
use strict;
use Carp;
use Net::OpenID2::Association::Association;
use Net::OpenID2::Association::DiffieHellmanSession;

use Exporter;
use base 'Exporter';
our @EXPORT_OK = qw( NO_ENCRYPTION EMPTY DH_SHA1 DH_SHA256 );

use constant NO_ENCRYPTION => 'no-encryption';
use constant EMPTY         => ' ';
use constant DH_SHA1       => 'DH-SHA1';
use constant DH_SHA256     => 'DH-SHA256';

my $NO_ENCRYPTION_SHA1MAC = __PACKAGE__->new(
   NO_ENCRYPTION ,
   undef ,
   TYPE_HMAC_SHA1 ,
   0
);

my $NO_ENCRYPTION_COMPAT_SHA1MAC = __PACKAGE__->new(
    EMPTY ,
    undef ,
    TYPE_HMAC_SHA1 ,
    1
);

my $NO_ENCRYPTION_SHA256MAC = __PACKAGE__->new(
   NO_ENCRYPTION ,
   undef ,
   TYPE_HMAC_SHA256 ,
   2
);

my $DH_SHA1 = __PACKAGE__->new(
   DH_SHA1 ,
   H_ALGORITHM_SHA1 ,
   TYPE_HMAC_SHA1 ,
   3
);

my $DH_SHA256 = __PACKAGE__->new(
   DH_SHA256 ,
   H_ALGORITHM_SHA256 ,
   TYPE_HMAC_SHA256 ,
   5
);




sub new {
  my $class = shift;
  my $self = { _sess_type   => $_[0] ,
               _h_algorithm => $_[1] ,
               _assoc_type  => $_[2] ,
               _order       => $_[3] ,
             };
  return bless( $self , $class );
}

# Signatures:
# create( $session_type )
# create( $session_type , $association_type )
sub create {
  my ( $class , $session_type , $assoc_type ) = @_;
  ref $class and croak( "Static method\n" );
  defined $session_type or croak( "Session type required\n" );
  $assoc_type ||= TYPE_HMAC_SHA1;

  if( $session_type eq NO_ENCRYPTION ){
    if( $assoc_type eq TYPE_HMAC_SHA1 ){
      return $NO_ENCRYPTION_SHA1MAC;
    } elsif ( $assoc_type eq TYPE_HMAC_SHA256 ){
      return $NO_ENCRYPTION_SHA256MAC;
    } else {
      croak( "Unknown session type: $assoc_type\n" );
    }
  } elsif( ($session_type=~/^\s*$/) or (! defined $session_type ) ) {
    if( $assoc_type eq TYPE_HMAC_SHA1 ){
      return $NO_ENCRYPTION_COMPAT_SHA1MAC;
    } else {
      croak( "Unknown association type: $assoc_type\n" );
    }
  } elsif ( ($session_type eq DH_SHA1) and ($assoc_type eq TYPE_HMAC_SHA1) ){
    return $DH_SHA1;
  } elsif ( $session_type eq DH_SHA256 ){
    return $DH_SHA256;
  } else {
    croak( "Unknown session/association type: $session_type/$assoc_type\n" );
  }
}

sub get_association_type { return $_[0]->{_assoc_type} }

sub get_session_type { return $_[0]->{_sess_type} }

sub get_h_algorithm { return $_[0]->{_h_algorithm} }

sub is_better {
  my( $self , $other ) = @_;

  unless( ref $other && $other->isa( 'Net::OpenID2::Association::AssociationSessionType' ) ){
    croak( "Not a valid object type\n" );
  }

  return $self->{_order} > $other->{_order};
}

1;
