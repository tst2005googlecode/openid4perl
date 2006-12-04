package Net::OpenID2::Message::DirectError;

use warnings;
use strict;
use Carp;
use base('Net::OpenID2::Message::Message');

sub new {
  my( $class , $arg ) = @_;

  if ( ref $arg && $arg->isa( 'Net::OpenID2::Message::ParameterList' ) ) {
    # ParameterList constructor
    my $self = Net::OpenID2::Message::Message->new( $arg );
    return bless $self , $class;
  } elsif ( defined $arg ) {
    # String constructor
    my $self = Net::OpenID2::Message::Message->new();
    bless $self , $class;
    $self->_set_param_value('error' , $arg);
    return $self
  } else {
    croak("Invalid argument\n");
  }
}

sub set_error_msg {
  my( $self , $message ) = @_;
  defined $message or croak("No message provided\n");
  $self->_set_param_value('error' , $message );
}

sub set_contact {
  my( $self , $contact ) = @_;
  defined $contact or croak("No contact provided\n");
  $self->_set_param_value('contact' , $contact );
}

sub set_reference {
  my( $self , $reference ) = @_;
  defined $reference or croak("No reference provided\n");
  $self->_set_param_value('reference' , $reference );
}

1;

__END__

=head1 NAME

Net::OpenID2::Message::DirectError

=head1 METHODS

=head2 new( $message )

=head2 new( $parameter_list )

=head2 set_error_msg( $message )

=head2 set_contact( $contact )

=head2 set_reference( $reference )

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut

