package Net::OpenID2::Discovery::HtmlResolver;

use warnings;
use strict;
use Carp;
use LWP::UserAgent;
use Net::OpenID2::Discovery::DiscoveryInformation qw( OPENID_1_0 );

use constant DEFAULT_MAX_REDIRECTS => 10;
use constant DEFAULT_MAX_HTML_SIZE => 100_000;
use constant DEFAULT_CONN_TIMEOUT  => 3;
use constant OPENID_SERVER         => 'openid.server';
use constant OPENID_DELEGATE       => 'openid.delegate';

sub new {
  my $class = shift;
  my $self = { _max_redirects  => DEFAULT_MAX_REDIRECTS ,
               _max_html_size  => DEFAULT_MAX_HTML_SIZE ,
               _conn_timeout   => DEFAULT_CONN_TIMEOUT  };
  return bless( $self , $class );
}

# seconds, not ms
sub conn_timeout {
  my( $self , $arg ) = @_;
  $self->{_conn_timeout} = $arg if $arg;
  return $self->{_conn_timeout };
}

sub max_html_size {
  my( $self , $arg ) = @_;
  $self->{_max_html_size} = $arg if $arg;
  return $self->{_max_html_size };
}

sub max_redirects {
  my( $self , $arg ) = @_;
  $self->{_max_redirects} = $arg if $arg;
  return $self->{_max_redirects };
}

# no socket_timeout() as in Java

#TODO: be able to pass a HTTP::Response object for testing
sub discover{

  my( $self , $identifier ) = @_;
  unless( ref $identifier && $identifier->isa( 'Net::OpenID2::Discovery::UrlIdentifier' ) ){
    croak( "Missing or invalid identifier\n" );
  }

  my $agent = LWP::UserAgent->new( agent => 'Net::OpenID2' ,
                                   max_size => $self->max_html_size ,
                                   max_redirect => $self->max_redirects ,
                                   timeout => $self->conn_timeout );

  my $response = $agent->get( $identifier->get_identifier );
  unless( $response->is_success ){
    carp( 'GET request failed on identifier: ' . $response->status_line );
    return;
  }

  my %link_for;
  for( $response->header( 'link' ) ){
    next unless /<(.+)>.+rel="(.+)"/;
    $link_for{$2} = $1;
  }

  unless( $link_for{&OPENID_SERVER} ){
    carp( 'No ' . OPENID_SERVER . " link found in the response\n" );
    return;
  }

  my $claimed_identifier = Net::OpenID2::Discovery::Discovery->parse_identifier( $response->base->as_string );
  my $openid_delegate = Net::OpenID2::Discovery::Discovery->parse_identifier( $link_for{&OPENID_DELEGATE} );
  my $args = { idp_endpoint        => $link_for{&OPENID_SERVER} ,
               claimed_identifier  => $claimed_identifier ,
               delegate_identifier => $openid_delegate ,
               version             => OPENID_1_0 ,
             };
  return Net::OpenID2::Discovery::DiscoveryInformation->new( $args );
}


1;
