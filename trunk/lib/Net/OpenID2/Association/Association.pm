package Net::OpenID2::Association::Association;

use warnings;
use strict;
use Carp;
use Exporter;
use base 'Exporter';
use Date::Calc;
use Date::Calc::Object;
use Digest::SHA qw( hmac_sha1_base64 hmac_sha256_base64 );

our @EXPORT = qw ( TYPE_HMAC_SHA1
                   TYPE_HMAC_SHA256
                   HMAC_SHA1_ALGORITHM
                   HMAC_SHA256_ALGORITHM
                   HMAC_SHA1_KEYSIZE
                   HMAC_SHA256_KEYSIZE
                 );

our @EXPORT_OK = qw( generate_mac_sha1_key
                     generate_mac_sha256_key
                     generate_mac_key
                   );

use constant FAILED_ASSOC_HANDLE      => ' ';
use constant FAILED_ASSOC_TYPE        => ' ';
use constant FAILED_ASSOC_MAC         => ' ';
use constant TYPE_HMAC_SHA1           => 'HMAC-SHA1';
use constant TYPE_HMAC_SHA256         => 'HMAC-SHA256';
use constant HMAC_SHA1_ALGORITHM      => 'HmacSHA1';
use constant HMAC_SHA256_ALGORITHM    => 'HmacSHA256';
use constant HMAC_SHA1_KEYSIZE        => 160;
use constant HMAC_SHA256_KEYSIZE      => 256;


sub new {
  my( $class , $type , $handle , $mac_key , $expiry ) = @_;

  defined $type    or croak( "No type provided\n" );
  defined $handle  or croak( "No handle provided\n" );
  defined $mac_key or croak( "No MAC key provided\n" );
  defined $expiry  or croak( "No expiry provided\n" );
  unless( ref $expiry and $expiry->isa( 'Date::Calc' ) ){
    my $seconds = $expiry;
    $seconds =~ /^\d+$/ or croak("Expiry is invalid: must be a delta of seconds or a Date::Calc::Object\n" );
    $expiry = Date::Calc->gmtime();
    $expiry += [0,0,0,0,0,$seconds]; # [Y,M,D,H,M,S]
  }

  return bless( { _type    => $type ,
                  _handle  => $handle ,
                  _mac_key => $mac_key ,
                  _expiry  => $expiry ,
                } , $class );
}

# A factory used by the RP. MAC is created by the IDP
sub create_hmac_sha1 {
 my $class = shift;
  return __PACKAGE__->new( TYPE_HMAC_SHA1 , @_ );
}

# A factory used by the RP. MAC is created by the IDP
sub create_hmac_sha256 {
  my $class = shift;
  return __PACKAGE__->new( TYPE_HMAC_SHA256 , @_ );
}

sub generate {
  my( $class , $type , $handle , $expiry_in ) = @_;
  ref $class         and croak( "Static method\n" );
  defined $type      or croak( "No type defined\n" );
  defined $handle    or croak( "No handle defined\n" );
  defined $expiry_in or croak( "No expiry defined\n" );

  if( $type eq TYPE_HMAC_SHA1 ){
    return generate_hmac_sha1( $handle , $expiry_in );
  } elsif( $type eq TYPE_HMAC_SHA256 ){
    return generate_hmac_sha256( $handle , $expiry_in );
  } else {
    croak( "Unknown association type: $type\n" );
  }
}

sub generate_hmac_sha1 {
  my( $class , $handle , $expiry_in ) = @_;
  ref $class         and croak( "Static method\n" );
  defined $handle    or croak( "No handle provided\n" );
  defined $expiry_in or croak( "No seconds to expiry provided\n" );

  return __PACKAGE__->new( TYPE_HMAC_SHA1 , $handle , generate_mac_sha1_key() , $expiry_in );
}

sub generate_hmac_sha256 {
  my( $class , $handle , $expiry_in ) = @_;
  ref $class         and croak( "Static method\n" );
  defined $handle    or croak( "No handle provided\n" );
  defined $expiry_in or croak( "No seconds to expiry provided\n" );

  return __PACKAGE__->new( TYPE_HMAC_SHA256 , $handle , generate_mac_sha256_key() , $expiry_in );
}

sub generate_mac_sha1_key {
  return generate_mac_key( HMAC_SHA1_ALGORITHM );
}

sub generate_mac_sha256_key {
  return generate_mac_key( HMAC_SHA256_ALGORITHM );
}

# interface differs from the Java API, which also passes a key size to this
# method for use with the JCE.  For our purposes, key size can be determined
# from the algorithm.
sub generate_mac_key {
  defined (my $algorithm = shift ) or croak( "No algorithm provided\n" );
  my $size;
  if( $algorithm eq HMAC_SHA1_ALGORITHM ){
    $size = HMAC_SHA1_KEYSIZE;
  } elsif ( $algorithm eq HMAC_SHA256_ALGORITHM ){
    $size = HMAC_SHA256_KEYSIZE;
  } else {
    croak( "Invalid algorithm: $algorithm\n" );
  }

  use Crypt::Random qw( makerandom );
  return makerandom( Size => $size , Strength => 1 );
}

sub get_failed_association {
  my( $class , $expiry_in ) = @_;
  ref $class and croak( "Static method\n" );
  defined $expiry_in or croak( "No expiry time specified\n" );

  my $now = Date::Calc->gmtime;
  return __PACKAGE__->new( FAILED_ASSOC_TYPE ,
                           FAILED_ASSOC_HANDLE ,
                           FAILED_ASSOC_MAC ,
                           $now + [0,0,0,0,0,$expiry_in] );

}

sub sign {
  my( $self , $text ) = @_;
  defined $text or croak( "No text provided to sign\n" );
  my $type = $self->get_type;
  my $mac_key = $self->get_mac_key;

  if( $type eq TYPE_HMAC_SHA1 ){
    return hmac_sha1_base64( $text , $mac_key );
  } elsif( $type eq TYPE_HMAC_SHA256 ){
    return hmac_sha256_base64( $text , $mac_key );
  } else {
    croak("Unknown signature algorithm: $type\n" );
  }
}

sub verify_signature {
  my( $self , $text , $signature ) = @_;
  defined $text      or croak( "No text provided\n" );
  defined $signature or croak( "No signature provided\n" );

  return $signature eq $self->sign( $text );
}

sub get_type { return $_[0]->{_type} }

sub get_handle { return $_[0]->{_handle} }

sub get_mac_key { return $_[0]->{_mac_key} }

sub get_expiry { return $_[0]->{_expiry} }

sub has_expired { return( $_[0]->get_expiry lt Date::Calc->gmtime ) }

sub is_hmac_supported { return 1 } # Mirroring the Java API

sub is_hmac_sha1_supported { return 1 } # Mirroring the Java API

sub is_hmac_sha256_supported { return 1 } # Mirroring the Java API

1;
