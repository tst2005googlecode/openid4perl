package Net::OpenID2::Association::DiffieHellmanSession;

## TODO: class not implemented

use warnings;
use strict;
use Carp;
use Crypt::DH;
use Math::BigInt lib => 'GMP';
use MIME::Base64 qw( decode_base64 encode_base64 );
use Digest::SHA qw( sha1 sha256 );
use Exporter;
use base 'Exporter';
our @EXPORT = qw( DEFAULT_MODULUS_HEX
                  DEFAULT_GENERATOR
                  ALGORITHM
                  H_ALGORITHM_SHA1
                  H_ALGORITHM_SHA256 );

use constant DEFAULT_MODULUS_HEX =>
  'DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E' .
  'F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557' .
  '7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382' .
  '6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB' ;
use constant DEFAULT_GENERATOR => 2;
use constant ALGORITHM => 'DH';
use constant H_ALGORITHM_SHA1 => 'SHA1';
use constant H_ALGORITHM_SHA256 => 'SHA256';


# handle decimal, hex and base64 as modulus and base
sub create {
  my( $class , $type , $modulus , $base ) = @_;
  ref $class && croak( "Static method\n" );
  unless( ref $type and $type->isa( 'Net::OpenID2::Association::AssociationSessionType' ) ){
    croak( "Invalid type object" );
  }

  $modulus ||= DEFAULT_MODULUS_HEX;
  $base    ||= DEFAULT_GENERATOR;

  my $dh = Crypt::DH->new( p => string2bigint($modulus) , g => string2bigint($base) );
  $dh->generate_keys;
  my $self = { _type => $type , _dh => $dh } ;
  return bless( $self , $class );
}

sub string2bigint {
  my $input = shift;

  if ( ($input =~ m{^[A-Za-z0-9+/=]+$}) and !( length($input) % 4) ) {
    # is it base64-encoded?
    $input = decode_base64( $input );
    $input = bytesToNum( $input );
  } elsif ( $input =~ /^[0-9a-fA-F]+$/ and $input !~ /^0x/i ) {
    # if it's hex, make sure it's prefixed with '0x'
    $input = "0x$input";
  }

  return Math::BigInt->new( $input );
}

sub get_dh{ return $_[0]->{_dh} }

# all methods returning from a Crypt::DH return Math::BigInt object
sub get_generator{ return $_[0]->get_dh->g }

sub get_modulus{ return $_[0]->get_dh->p }

sub get_private_key{ return $_[0]->get_dh->priv_key }

sub get_public_key{ return $_[0]->get_dh->pub_key }

sub get_type{ return $_[0]->{_type} }

sub public_key_to_string { encode_base64( numToBytes($_[0]->get_public_key))  }

sub is_dh_supported{
  # TODO: Compare with session type with constant values instead of regex
  my $self = shift;
  my $sess_type = $self->get_type->get_session_type;
  return $sess_type =~ /dh/i;
}

sub is_dh_sha1_supported{
  # TODO: Compare with session type with constant values instead of regex
  my $self = shift;
  my $sess_type = $self->get_type->get_session_type;
  return $sess_type =~ /sha_?1/i;
}

sub is_dh_sha256_supported{
  # TODO: Compare with session type with constant values instead of regex
  my $self = shift;
  my $sess_type = $self->get_type->get_session_type;
  return $sess_type =~ /sha_?256/i;
}

sub get_digested_ZZ {
  my( $self , $pub_key )  = @_;
  my $algorithm = $self->get_type->get_h_algorithm;
  $pub_key = bytesToNum( decode_base64( $pub_key ) );

  my $shared_secret = numToBytes( $self->get_dh->compute_secret( $pub_key ) );
  my $hashed;

  if( $algorithm eq H_ALGORITHM_SHA1 ){
    $hashed = sha1( $shared_secret );
  } elsif( $algorithm eq H_ALGORITHM_SHA256 ){
    $hashed = sha256( $shared_secret );
  } else {
    croak "Can't hash using algorithm $algorithm\n";
  }
  return $hashed;
}

# base64(H(btwoc(g ^ (xa * xb) mod p)) XOR MAC_key )
sub encrypt_mac_key {
  my( $self , $mac_key , $consumer_public_key_base64 ) = @_;
  defined $mac_key or croak( "No MAC key provided\n" );
  defined $consumer_public_key_base64 or croak( "No public key provided\n" );

  my $digested_shared_secret = $self->get_digested_ZZ( $consumer_public_key_base64 );
  $mac_key = decode_base64( $mac_key );

  return encode_base64( $mac_key ^ $digested_shared_secret );
}

sub decrypt_mac_key {
  my( $self , $mac_key_base64 , $server_public_key_base64 ) = @_;
  defined $mac_key_base64 or croak( "No MAC key provided\n" );
  defined $server_public_key_base64 or croak( "No public key provided\n" );

  my $digested_shared_secret = $self->get_digested_ZZ( $server_public_key_base64 );
  my $mac_key = decode_base64( $mac_key_base64 );

  return encode_base64( $mac_key ^ $digested_shared_secret );
}






########################################################################

# Thanks to Dag @ JanRain for these two helpful functions!

sub numToBytes {
  my ($n) = @_;
  if ($n < 0) {
    die "numToBytes takes only positive integers.";
  }
  my @bytes = ();
  # get a big-endian base 256 representation of n
  while ($n) {
    unshift( @bytes, $n % 256 );
    $n = $n >> 8;
  }
  # first byte high bit is the sign bit
  if ($bytes[0] > 127) {
    unshift( @bytes, 0);
  }
  my $string = pack('C*',@bytes);
  return $string;
}


sub bytesToNum {
  my ($string) = @_;
  unless($string) {
    warn "empty string passed to bytesToNum";
    return 0;
  }
  my @bytes = unpack('C*',$string);
  my $n = Math::BigInt->new(0);
  # high bit set means negative in twos complement; invalid for us
  return undef if ($bytes[0] > 127);
  for (@bytes) {
    $n = $n << 8;
    $n = $n + $_;
  }
  return $n;
}

1;
