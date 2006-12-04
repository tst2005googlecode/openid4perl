package Net::OpenID2::Message::MessageExtension;

use warnings;
use strict;
use Carp;

sub new { croak("Not implemented\n") }

sub get_type_uri { croak("Not implemented\n") }

sub get_parameters { croak("Not implemented\n") }

sub set_parameters { croak("Not implemented\n") }

sub provides_identifier { croak("Not implemented\n") }

1;

__END__

=head1 NAME

Net::OpenID2::Message::MessageExtention

Interface for building OpenID extensions.

Classes that implement this interface should provide a default constructor
and register their Type URIs with the MessageExtensionFactory.

=head1 METHODS

=head2 get_type_uri()

Gets the TypeURI that identifies a extension to the OpenID protocol.

=head2 get_parameters()

Returns the extension parameters as an instance of
L<Net::OpenID2::Message::ParameterList>

Implementations MUST NOT prefix the parameter names with
"openid.<alias>". The alias is managed internally by the Message class,
when a extension is attached to an OpenID messaage.

=head2 set_parameters( $params )

Sets the extension parameters.  C<$params> must be an instance of
L<Net::OpenID2::Message::ParameterList>

Implementations MUST NOT prefix the parameter names with
"openid.<alias>". The alias is managed internally by the Message class,
when a extension is attached to an OpenID messaage.

=head2 provides_identifier()

Used by the core OpenID authentication implementation to learn whether
an extension provies authentication services.

If the extension provides authentication services,
the 'openid.identity' and 'openid.signed' parameters are optional.

=over

=item Returns

True if the extension provides authentication services, false
otherwise.

=back

=head1 SEE ALSO

L<Net::OpenID2::Message::MessageExtentionFactory>
L<Net::OpenID2::Message::Message>

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
