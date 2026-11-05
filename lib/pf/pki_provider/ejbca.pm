package pf::pki_provider::ejbca;

=head1 NAME

pf::pki_provider::ejbca

=cut

=head1 DESCRIPTION

PKI provider for EJBCA (https://www.ejbca.org). Uses the EJBCA REST API
(authenticated with a client certificate) to create an end entity and enroll a
PKCS12 keystore for it.

=cut

use strict;
use warnings;
use Moo;
use JSON::MaybeXS qw(encode_json decode_json);
use LWP::UserAgent;
use HTTP::Request;
use MIME::Base64 qw(decode_base64);
use URI::Escape qw(uri_escape);
use DateTime::TimeZone;
use DateTime::Format::Strptime;
use pf::constants;
use pf::log;
use pf::util qw(isenabled);

extends 'pf::pki_provider';

sub module_description { 'EJBCA' }

=head1 ATTRIBUTES

=head2 proto

http or https

=cut

has proto => (is => 'rw', default => 'https');

=head2 host

EJBCA host

=cut

has host => (is => 'rw', default => '127.0.0.1');

=head2 port

EJBCA port

=cut

has port => (is => 'rw', default => '8443');

=head2 client_cert_path

Client certificate used to authenticate against the EJBCA REST API

=cut

has client_cert_path => (is => 'rw');

=head2 client_key_path

Private key of the client certificate

=cut

has client_key_path => (is => 'rw');

=head2 api_ca_path

Optional CA certificate used to validate the EJBCA TLS server certificate.
The system trust store is used when empty.

=cut

has api_ca_path => (is => 'rw');

=head2 ca_name

Name of the EJBCA certificate authority that issues the certificates

=cut

has ca_name => (is => 'rw');

=head2 certificate_profile

EJBCA certificate profile name

=cut

has certificate_profile => (is => 'rw');

=head2 end_entity_profile

EJBCA end entity profile name

=cut

has end_entity_profile => (is => 'rw');

=head2 key_algorithm

Key algorithm of the generated key pair (RSA or ECDSA)

=cut

has key_algorithm => (is => 'rw', default => 'RSA');

=head2 key_spec

Key size (RSA) or curve name (ECDSA)

=cut

has key_spec => (is => 'rw', default => '2048');

=head2 revocation_reason

Reason used when the certificate is revoked

=cut

has revocation_reason => (is => 'rw', default => 'CESSATION_OF_OPERATION');

=head2 base_path

Base path of the EJBCA REST API

=cut

has base_path => (is => 'ro', default => '/ejbca/ejbca-rest-api/v1');

=head1 METHODS

=head2 _user_agent

Builds the HTTP client with the TLS client certificate

=cut

sub _user_agent {
    my ($self) = @_;
    my %ssl_opts;
    $ssl_opts{SSL_cert_file} = $self->client_cert_path if $self->client_cert_path;
    $ssl_opts{SSL_key_file}  = $self->client_key_path  if $self->client_key_path;
    if ($self->api_ca_path) {
        $ssl_opts{SSL_ca_file}       = $self->api_ca_path;
        $ssl_opts{verify_hostname}   = 1;
    }
    return LWP::UserAgent->new(timeout => 30, ssl_opts => \%ssl_opts);
}

=head2 _request

Send a JSON request to the EJBCA REST API. Returns the HTTP::Response

=cut

sub _request {
    my ($self, $method, $path, $payload) = @_;
    my $url = sprintf("%s://%s:%s%s%s", $self->proto, $self->host, $self->port, $self->base_path, $path);
    my $req = HTTP::Request->new($method => $url);
    $req->header('Accept' => 'application/json');
    if (defined $payload) {
        $req->header('Content-Type' => 'application/json');
        $req->content(encode_json($payload));
    }
    return $self->_user_agent->request($req);
}

=head2 _escape_dn

Escape a value so it can be used in a distinguished name

=cut

sub _escape_dn {
    my ($value) = @_;
    $value =~ s/([,+"\\<>;=])/\\$1/g;
    return $value;
}

=head2 _subject_dn

Builds the subject DN from the common name and the provider attributes

=cut

sub _subject_dn {
    my ($self, $cn) = @_;
    my @parts = ("CN=" . _escape_dn($cn));
    my @map = (
        [ OU => $self->organizational_unit ],
        [ O  => $self->organization ],
        [ L  => $self->locality ],
        [ ST => $self->state ],
        [ C  => $self->country ],
    );
    for my $item (@map) {
        my ($key, $val) = @$item;
        push @parts, "$key=" . _escape_dn($val) if defined $val && $val ne '';
    }
    return join(',', @parts);
}

=head2 _end_date

Converts the node unregistration date to the format expected by EJBCA

=cut

sub _end_date {
    my ($self, $expiration) = @_;
    my $tz = $ENV{TZ} || DateTime::TimeZone->new( name => 'local' )->name();
    my $formatter = DateTime::Format::Strptime->new(pattern => "%F %T", time_zone => $tz);
    my $dt = $formatter->parse_datetime($expiration) or return undef;
    $dt->set_time_zone('UTC');
    return $dt->strftime("%Y-%m-%d %H:%M:%S+00:00");
}

=head2 get_bundle

Create the end entity in EJBCA and enroll a PKCS12 keystore for it

=cut

sub get_bundle {
    my ($self, $args) = @_;
    my $logger = get_logger();

    my $cn       = $args->{certificate_cn};
    my $email    = $args->{certificate_email};
    my $password = $args->{certificate_pwd};
    my $username = $cn;

    my $entity = {
        username                 => $username,
        password                 => $password,
        subject_dn               => $self->_subject_dn($cn),
        ca_name                  => $self->ca_name,
        certificate_profile_name => $self->certificate_profile,
        end_entity_profile_name  => $self->end_entity_profile,
        token                    => 'P12',
    };
    if (defined $email && $email ne '' && $email ne 'not_needed') {
        $entity->{email} = $email;
        $entity->{subject_alt_name} = "rfc822Name=$email";
    }
    my $expiration = $args->{unregdate};
    if (defined $expiration && $expiration ne '' && isenabled($self->certificate_validity_time_from_unreg_date)) {
        if (my $end = $self->_end_date($expiration)) {
            $entity->{extension_data} = [ { name => 'enddate', value => $end } ];
        }
    }

    my $res = $self->_request(POST => '/endentity', $entity);
    if (!$res->is_success) {
        # The end entity may already exist (re-enrollment): reset it to NEW with the new password
        $logger->info("End entity creation for $username returned " . $res->status_line . ", trying to reset its status");
        my $reset = $self->_request(POST => '/endentity/' . uri_escape($username) . '/setstatus', { password => $password, status => 'NEW' });
        if (!$reset->is_success) {
            $logger->warn("EJBCA end entity creation failed for $username: " . $res->status_line . " " . ($res->decoded_content // ''));
            return;
        }
    }

    my $enroll = $self->_request(POST => '/certificate/enrollkeystore', {
        username => $username,
        password => $password,
        key_alg  => $self->key_algorithm,
        key_spec => $self->key_spec,
    });
    if (!$enroll->is_success) {
        $logger->warn("EJBCA keystore enrollment failed for $username: " . $enroll->status_line . " " . ($enroll->decoded_content // ''));
        return;
    }

    return $self->_extract_keystore($enroll);
}

=head2 _extract_keystore

The keystore is either returned as raw binary or as a base64 string in a JSON document

=cut

sub _extract_keystore {
    my ($self, $res) = @_;
    my $content = $res->content;
    my $type = $res->header('Content-Type') // '';
    if ($type =~ m{json}i) {
        my $data = eval { decode_json($content) };
        if (ref($data) eq 'HASH') {
            my $b64 = $data->{keystore} // $data->{certificate} // $data->{certificate_data};
            return decode_base64($b64) if defined $b64;
        }
        get_logger->warn("Unable to find the keystore in the EJBCA response");
        return;
    }
    return $content;
}

=head2 revoke

Revoke all the certificates of the end entity

=cut

sub revoke {
    my ($self, $cn) = @_;
    my $logger = get_logger();
    my $res = eval {
        $self->_request(POST => '/endentity/' . uri_escape($cn) . '/revoke', { reason => $self->revocation_reason });
    };
    if ($@ || !$res || !$res->is_success) {
        $logger->debug("Unable to revoke certificate associated with this cn $cn");
        return $FALSE;
    }
    return $TRUE;
}

=head1 AUTHOR

Inverse inc. <info@inverse.ca>

=head1 COPYRIGHT

Copyright (C) 2005-2026 Inverse inc.

=head1 LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
USA.

=cut

1;
