package Net::OpenID2::Consumer::NonceVerifier;

use warnings;
use strict;
use Carp;

use constant OK                => 0;
use constant SEEN              => 1;
use constant INVALID_TIMESTAMP => 2;
use constant TOO_OLD           => 3;


sub new { croak( "Not implemented!\n" ) }

sub seen { croak( "Not implemented!\n" ) }

sub get_max_age { croak( "Not implemented!\n" ) }

sub set_max_age { croak( "Not implemented!\n" ) }

1;



=head1 NAME

Net::OpenID2::Consumer::NonceVerifier

Abstract class for implementations.

=head1 CONSTANTS

=over

=item OK

This nonce is valid and it has not been seen before. Nonce should be accepted.

=item SEEN

The nonce has been seen before. Nonce should be rejected.

=item INVALID_TIMESTAMP

The timestamp of the nonce is invalid, it cannot be parsed. Nonce should
be rejected.

=item TOO_OLD

The timestamp of the nonce is too old and it is not tracked anymore. Nonce
should be rejected.

=back

=head1 METHODS

=head2 seen( $idp_url , $nonce )

Checks if a nonce has been seen before. It also checks if the time
stamp at the beginning of the nonce is valid.  Also, if old nonces are
discarded then it should check if the time stamp for this nonce is
still valid.

Returns true only if this nonce has a valid time stamp, the time stamp
did not age, and the nonce has not been seen before.

=head2 get_max_age()

Returns the expiration timeout for nonces in seconds.

=head2 set_max_age( $age )

Set the expiration timeout for nonces in seconds.

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut

