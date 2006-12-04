package Net::OpenID2::Message::VerifyRequest;

use warnings;
use strict;
use Carp;
use Net::OpenID2::Message::AuthSuccess;
use English qw( -no_match_vars );

use base('Net::OpenID2::Message::Message');

use constant MODE_CHKAUTH => 'check_authentication';

sub new {
  my( $class , $arg ) = @_;
  $arg or croak( "No argument provided\n");
  ref $arg or croak( "Invalid argument\n");

  if( $arg->isa('Net::OpenID2::Message::ParameterList') ){
    my $self = Net::OpenID2::Message::Message->new( $arg );
    return bless $self , $class;
  } elsif ( $arg->isa('Net::OpenID2::Message::AuthSuccess') ){
    my $self = Net::OpenID2::Message::Message->new();
    bless $self , $class;
    $self->get_params->copy_of( $arg->get_params );
    $self->get_params->remove_parameters('openid.mode');
    $self->get_params->set( Net::OpenID2::Message::Parameter->new( 'openid.mode' , MODE_CHKAUTH ) );
    unless( $self->is_valid ){
      croak("Cannot generate valid verification request from authentication response: "
            . $arg->www_form_encoding
            . "\n" );
    }
    return $self;
  } else {
    croak("Invalid argument\n");
  }
}

sub get_handle {
  my $self = shift or croak("Instance method\n");
  return $self->_get_param_value('openid.assoc_handle');
}

sub get_invalidate_handle {
  my $self = shift or croak("Instance method\n");
  return $self->_get_param_value('openid.invalidate_handle');
}

sub get_sig {
  my $self = shift or croak("Instance method\n");
  return $self->_get_param_value('openid.sig');
}

sub is_valid {
  my $self = shift or croak("Instance method\n");
  return unless $self->SUPER::is_valid;

  my $mode = $self->_get_param_value('openid.mode');
  unless( $mode eq MODE_CHKAUTH ){
    carp( sprintf( "'openid.mode' should be '%s' but it's '%s'\n" ,
            MODE_CHKAUTH , $mode ));
    return;
  }

  # delegate the rest to AuthSuccess' is_valid()
  my $temp = Net::OpenID2::Message::ParameterList->new({});
  $temp->copy_of( $self->get_params );
  $temp->remove_parameters('openid.mode');
  $temp->set( Net::OpenID2::Message::Parameter->new('openid.mode' , $self->MODE_IDRES) );
  eval{ Net::OpenID2::Message::AuthSuccess->new( $temp ) }; # dies if invalid
  return if $EVAL_ERROR;

  return 1;
}

sub get_signed_text {
  my $self = shift or croak("Instance method\n");
  # delegate to AuthSuccess' get_signed_text()
  my $temp = Net::OpenID2::Message::ParameterList->new();
  $temp->copy_of( $self->get_params );
  $temp->remove_parameters('openid.mode');
  $temp->set( Net::OpenID2::Message::Parameter->new('openid.mode' , $self->MODE_IDRES) );
  return Net::OpenID2::Message::AuthSuccess->new( $temp )->get_signed_text;
}


1;

__END__

=head1 NAME

Net::OpenID2::Message::VerifyRequest


=head1 CONSTANTS

=over

=item MODE_CHKAUTH

=back

=head1 METHODS

=head2 new( $auth_success )

=head2 new( $parameter_list )

=head2 get_handle()

=head2 get_invalidate_handle()

=head2 get_sig()

=head2 get_signed_text()

=head2 is_valid()

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
