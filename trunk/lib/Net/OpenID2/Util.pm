package Net::OpenID2::Util;

use warnings;
use strict;
use Carp;
use Date::Calc::Object;
use Exporter;
use base qw( Exporter );

our @EXPORT_OK = qw( nonce2date );

sub nonce2date {
  my $nonce = shift or croak("No nonce provided\n");
  if( $nonce =~/(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})[Zz].*/ ){
    return Date::Calc->new( 1,$1,$2,$3,$4,$5,$6 );
  } else {
    return;
  }
}


1;

__END__

=head1 NAME

Net::OpenID2::Util - General utilities needed for Net::OpenID

=head1 SYNOPSIS

use Net::OpenID2::Util qw( nonce2date );

my $date = nonce2date( $nonce );

=head1 METHODS

=head2 nonce2date( $nonce )

Converts a nonce into a C<Date::Calc> object.  Nonce must be in the format described
in the OpenID specification.

=head3

=over

=item A C<Date::Calc> object if parse succeeds

=item C<undef> on failure

=back

=head1 AUTHOR

David Huska

=head1 COPYRIGHT

Copyright 2006 Sxip Identity Corporation

=cut
