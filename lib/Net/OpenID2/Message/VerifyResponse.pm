package Net::OpenID2::Message::VerifyResponse;

use warnings;
use strict;
use Carp;
use base('Net::OpenID2::Message::Message');

my @REQUIRED_FIELDS = qw( mode is_valid );

my @OPTIONAL_FIELDS = qw( invalidate_handle );

sub new {
  my( $class , $arg ) = @_;

  # ParameterList constructor
  if( $arg ){
    if( ref $arg && $arg->isa( 'Net::OpenID2::Message::ParameterList' ) ){
      my $self =  Net::OpenID2::Message::Message->new( $arg );
      return bless $self , $class;
    } else {
      croak("Invalid parameter\n");
    }
  }

  # no-arg constructor
  my $self = Net::OpenID2::Message::Message->new();
  bless $self , $class;

  $self->get_params->set( Net::OpenID2::Message::Parameter->new( 'mode' , $self->MODE_IDRES ));
  $self->set_signature_verified( 0 );
  return $self;
}

sub get_required_fields {
  return @REQUIRED_FIELDS;
}

sub set_signature_verified {
  my( $self , $verified ) = @_;
  $self or croak("Instance method\n");

  my $value = $verified ? 'true' : 'false';
  $self->get_params->set( Net::OpenID2::Message::Parameter->new('is_valid' , $value ));
}

sub is_signature_verified {
  my $self = shift or croak("Instance method\n");
  return( $self->_get_param_value('is_valid') eq 'true' );
}

sub set_invalidate_handle {
  my( $self , $handle ) = @_;
  defined $handle or croak("No handle provided\n");

  $self->_set_param_value('invalidate_handle' , $handle );
}

sub get_invalidate_handle {
  my $self = shift or croak("Instance method\n");
  return $self->_get_param_value('invalidate_handle');
}

sub is_valid {
  my $self = shift or croak("Instance method\n");

  return unless $self->SUPER::is_valid;

  unless( $self->_get_param_value('openid.mode') eq $self->MODE_IDRES ){
    carp('openid.mode is not ' . $self->MODE_IDRES . "\n" );
    return;
  }

  return $self->_get_param_value('is_valid') =~ /^(true|false)$/;
}

1;

__END__

=head1 NAME

Net::OpenID2::Message::VerifyResponse

=head1 METHODS

=head2 new()

=head2 new( $parameter_list )

=head2 get_required_fields()

=head2 is_signature_verified()

=head2 set_signature_verified( $bool )

=head2 get_invalidate_handle()

=head2 set_invalidate_handle( $handle )

=head2 is_valid()

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
