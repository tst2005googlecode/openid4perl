package Net::OpenID2::Consumer::VerificationResult;

use warnings;
use strict;
use Carp;

sub new { bless {_verified_id => '' , _idp_setup_url => ''} , $_[0] }

sub set_verified_id {
  my( $self , $id ) = @_;
  unless( ref $id and $id->isa( 'Net::OpenID2::Discovery::Identifier' ) ){
    croak( "Provided ID is invalid" );
  }
  $self->{_verified_id} = $id;
}

sub get_verified_id { return $_[0]->{_verified_id} }

sub set_idp_url {
  my( $self , $url ) = @_;
  $url or croak( "No URL provided\n" );
  $self->{_idp_setup_url} = $url;
}

sub get_idp_url { return $_[0]->{_idp_setup_url} }


1;

__END__

=head1 NAME

Net::OpenID2::Consumer::VerificationResult

=head1 METHODS

=head2 new()

Takes no parameters.  Returns a new object

=head2 set_verified_id( $id )

Sets the verified ID.  C<$id> must be an instance of
L<Net::OpenID2::Discovery::Identifier>.  This is the identifier on
which authentication and verification were performed succesfully and
which can be used henceforth by Relying Parties to identify the user.

=head2 get_verified_id()

Gets the verified ID.

=head2 set_idp_url( $url )

Sets the IDP setup_url parameter, if one was returned in a failure
response to a immediate authentication request (AuthImmediateFailure).

=head2 get_idp_url()

Gets the IDP setup_url parameter.

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
