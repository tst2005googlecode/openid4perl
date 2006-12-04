package Net::OpenID2::Discovery::Discovery;

use warnings;
use strict;
use Carp;
use English qw( -no_match_vars );
use LWP::UserAgent;
use Net::Yadis;
use XML::XPath;

use Net::OpenID2::Discovery::XriIdentifier;
use Net::OpenID2::Discovery::UrlIdentifier;
use Net::OpenID2::Discovery::DiscoveryInformation qw( OPENID_1_0 OPENID_2_0 IDENTIFIER_SELECT );
use Net::OpenID2::Discovery::HtmlResolver;


use constant XRI_PROXY => 'http://xri.net';

# return the appropriate identifier type based on the provided identifier
sub parse_identifier {
  my( $class , $identifier ) = @_;
  ref $class && croak "Can't be called on an instance\n";
  $identifier || croak "No identifier provided\n";

  # determine type based on scheme or XRI global context symbol
  if( $identifier =~ /^(?:xri|=|@|\+|\$)/ ){
    return new Net::OpenID2::Discovery::XriIdentifier( $identifier );
  } else {
    return new Net::OpenID2::Discovery::UrlIdentifier( $identifier );
  }
}

sub discover {
  my( $self , $identifier ) = @_;
  unless( ref $identifier and $identifier->isa( 'Net::OpenID2::Discovery::Identifier' ) ){
    croak( "Invalid identifier\n" );
  }

  my @discovered;
  if( $identifier->isa( 'Net::OpenID2::Discovery::XriIdentifier' ) ){
    my $xri = $identifier->get_identifier;
    my $url = XRI_PROXY . "/$xri";
    my $response = LWP::UserAgent->new()->get( $url , Accept => 'application/xrds+xml');
    unless( $response->is_success ){
      croak( "Couldn't GET $url: " . $response->status_line . "\n" );
    }
    @discovered = $self->_extract_discovery_info( Net::Yadis->new( $xri , $url , $response->content ) );
  } elsif( $identifier->isa( 'Net::OpenID2::Discovery::UrlIdentifier' )){
    my $url = $identifier->get_identifier;

    # try Yadis discovery
    my $yadis;
    eval{ $yadis = Net::Yadis->discover( $url ) };
    if( $EVAL_ERROR ){
      # Yadis failed, do HTML discovery
      push @discovered ,  Net::OpenID2::Discovery::HtmlResolver->discover( $identifier ) ;
    } else {
      @discovered = $self->_extract_discovery_info( $yadis );
    }
  } else {
    croak( "Unknown identifier type\n" );
  }
  return @discovered;
}


# returns a list of 'Net::OpenID2::Discovery::DiscoveryInformation' objects
# params: one Net::Yadis object after discovery
sub _extract_discovery_info {
  my( $self , $yadis ) = @_;
  my @discovered;
  my $canonical = $yadis->xrds_xpath->getNodeText( '/XRDS/XRD/CanonicalID' )->value; #TODO: handle multiple
  my $claimed_identifier = $canonical ? $self->parse_identifier( $canonical ) : undef ;

  # get info for 'identifier select', 'OpenID 2.0', and 'OpenID 1.0' services in that order
  foreach my $version ( &IDENTIFIER_SELECT , &OPENID_2_0 , &OPENID_1_0 ) {
    foreach my $service ( $yadis->services_of_type( $version ) ) {
      my $delegate = $service->xrds->getNodeText( '/Service/Delegate' )->value;
      foreach my $uri ( $service->uris ) {
        my $delegate_identifier = $delegate ? $self->parse_identifier( $delegate ) : undef ;
        my $args = { idp_endpoint        => $uri ,
                     claimed_identifier  => $claimed_identifier ,
                     delegate_identifier => $delegate_identifier ,
                     version             => $version ,
                   };
        push( @discovered , Net::OpenID2::Discovery::DiscoveryInformation->new( $args ) );
      }
    }
  }
  return @discovered;
}


1;
