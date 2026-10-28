package pf::Switch::Extreme::VOSS;

=head1 NAME

pf::Switch::Extreme::VOSS - Extreme Networks VOSS / Fabric Engine (VSP series)

=head1 SYNOPSIS

Wired 802.1X (EAP) and MAC authentication (NEAP) on the Extreme Networks
switches running VOSS or Fabric Engine, ports in MHSA mode.

=head1 STATUS

=over

=item VLAN of the switch VLAN map: Extreme-Dynamic-Client-Assignments = pv=<vlan>,ev=0 (VOSS 8.8 and later)

=item Role of the switch role map: Fabric Attach binding (Fabric-Attach-VLAN-ISID), <vlan>:<i-sid> or 0:<i-sid>

=item Access list of the switch role: additional attributes, one "Attribute-Name = value" per line,
for example the Extreme-Dynamic-Config features (DHCPSNOOP, DAI, IPSG, ...). IPSG is only sent with
DHCPSNOOP and DAI.

=item Deauthentication with a RADIUS Disconnect-Request

=item Port bounce with a RADIUS CoA-Request carrying Extreme-Dynamic-Config = PORTBOUNCE (VOSS 8.10 and later)

=back

=cut

use strict;
use warnings;
use base ('pf::Switch');
use Try::Tiny;
use pf::constants;
use pf::config qw(
    $WIRED_802_1X
    $WIRED_MAC_AUTH
);
use pf::Switch::constants;
use pf::util;
use pf::locationlog;
use pf::access_filter::radius;
use pf::util::radius_dictionary qw($RADIUS_DICTIONARY);
use pf::SwitchSupports qw(
    WiredMacAuth
    WiredDot1x
    RoleBasedEnforcement
    AccessListBasedEnforcement
);

our $DYNAMIC_CONFIG = 'Extreme-Dynamic-Config';
our $CLIENT_ASSIGNMENTS = 'Extreme-Dynamic-Client-Assignments';

sub description { 'Extreme Networks VOSS / Fabric Engine' }

=head2 returnRoleAttribute

The role of the switch role map is a Fabric Attach VLAN:I-SID binding

=cut

sub returnRoleAttribute { 'Fabric-Attach-VLAN-ISID' }

=head2 parseRequest

Take the MAC address from the User-Name when the request has no Calling-Station-Id

=cut

sub parseRequest {
    my ($self, $radius_request) = @_;
    my @request = $self->SUPER::parseRequest($radius_request);
    if (!$request[2]) {
        my $user_name = ref($radius_request->{'User-Name'}) eq 'ARRAY' ? $radius_request->{'User-Name'}[0] : $radius_request->{'User-Name'};
        $request[2] = clean_mac($user_name);
    }
    return @request;
}

=head2 returnRadiusAccessAccept

Return the VLAN in Extreme-Dynamic-Client-Assignments and add the attributes of the access list of the role

=cut

sub returnRadiusAccessAccept {
    my ($self, $args) = @_;
    my $logger = $self->logger;
    my $unfiltered = $args->{'unfiltered'};
    $args->{'unfiltered'} = $TRUE;
    my ($status, %radius_reply) = @{$self->SUPER::returnRadiusAccessAccept($args)};
    $args->{'unfiltered'} = $unfiltered;
    return [$status, %radius_reply] if ($status == $RADIUS::RLM_MODULE_USERLOCK);

    my $vlan = delete $radius_reply{'Tunnel-Private-Group-ID'};
    if (defined $vlan) {
        delete @radius_reply{qw(Tunnel-Medium-Type Tunnel-Type)};
        $radius_reply{$CLIENT_ASSIGNMENTS} = "pv=$vlan,ev=0";
    }

    if (isenabled($self->{_AccessListMap}) && defined($args->{'user_role'}) && $args->{'user_role'} ne '') {
        my $lines = $self->{'_access_lists'}{$args->{'user_role'}};
        $self->addAttributesFromLines(\%radius_reply, $lines) if defined $lines;
    }
    $self->checkDynamicConfig(\%radius_reply);

    my $radius_reply_ref = \%radius_reply;
    if (!isenabled($args->{'unfiltered'})) {
        my $filter = pf::access_filter::radius->new;
        my $rule = $filter->test('returnRadiusAccessAccept', $args);
        ($radius_reply_ref, $status) = $filter->handleAnswerInRule($rule, $args, $radius_reply_ref);
    }

    return [$status, %$radius_reply_ref];
}

=head2 addAttributesFromLines

Add the "Attribute-Name = value" lines to the reply, an attribute already in the reply or repeated
in the lines is sent several times

=cut

sub addAttributesFromLines {
    my ($self, $reply, $lines) = @_;
    my $logger = $self->logger;
    for my $line (split /\r?\n/, $lines) {
        next if $line =~ /^\s*(#|$)/;
        my ($name, $value) = $line =~ /^\s*([\w-]+)\s*=\s*(.*?)\s*$/;
        if (!defined $name || $value eq '') {
            $logger->warn("(" . $self->{'_id'} . ") Ignoring the access list line '$line', the format is 'Attribute-Name = value'");
            next;
        }
        if (!exists $RADIUS_DICTIONARY->{attr}{$name} && !exists $RADIUS_DICTIONARY->{avendors}{$name}) {
            $logger->warn("(" . $self->{'_id'} . ") Ignoring the access list line '$line', $name is not in the RADIUS dictionary");
            next;
        }
        if (!exists $reply->{$name}) {
            $reply->{$name} = $value;
        } elsif (ref($reply->{$name}) eq 'ARRAY') {
            push @{$reply->{$name}}, $value;
        } else {
            $reply->{$name} = [$reply->{$name}, $value];
        }
        $logger->info("(" . $self->{'_id'} . ") Added $name = $value to the returned RADIUS Access-Accept");
    }
}

=head2 checkDynamicConfig

IP Source Guard needs DHCP Snooping and Dynamic ARP Inspection: remove IPSG from
Extreme-Dynamic-Config when they are not both in the reply

=cut

sub checkDynamicConfig {
    my ($self, $reply) = @_;
    return if !exists $reply->{$DYNAMIC_CONFIG};
    my @values = ref($reply->{$DYNAMIC_CONFIG}) eq 'ARRAY' ? @{$reply->{$DYNAMIC_CONFIG}} : ($reply->{$DYNAMIC_CONFIG});
    my %features = map { uc($_) => 1 } @values;
    return if !$features{IPSG} || ($features{DHCPSNOOP} && $features{DAI});

    $self->logger->warn("(" . $self->{'_id'} . ") Not returning $DYNAMIC_CONFIG = IPSG: IP Source Guard needs DHCPSNOOP and DAI");
    @values = grep { uc($_) ne 'IPSG' } @values;
    if (@values == 0) {
        delete $reply->{$DYNAMIC_CONFIG};
    } else {
        $reply->{$DYNAMIC_CONFIG} = @values == 1 ? $values[0] : \@values;
    }
}

=head2 deauthTechniques

Return the reference to the deauth technique or the default deauth technique.

=cut

sub deauthTechniques {
    my ($self, $method, $connection_type) = @_;
    my $default = $SNMP::RADIUS;
    my %tech = (
        $SNMP::RADIUS => 'deauthenticateMacRadius',
    );

    if (!defined($method) || !defined($tech{$method})) {
        $method = $default;
    }
    return $method, $tech{$method};
}

=head2 supporteddeauthTechniques

Return the supported deauthentication techniques

=cut

sub supporteddeauthTechniques {
    my ($self) = @_;
    return (
        $SNMP::RADIUS => 'deauthenticateMacRadius',
    );
}

=head2 wiredeauthTechniques

Disconnect-Request for the 802.1X and MAC authentication sessions

=cut

sub wiredeauthTechniques {
    my ($self, $method, $connection_type) = @_;
    return $self->deauthTechniques($method, $connection_type);
}

=head2 deauthenticateMacRadius

Deauthenticate a wired endpoint with a RADIUS Disconnect-Request

=cut

sub deauthenticateMacRadius {
    my ($self, $ifIndex, $mac) = @_;
    my $logger = $self->logger;
    if (!$self->isProductionMode()) {
        $logger->info("not in production mode... we won't perform deauthentication");
        return 1;
    }

    $logger->debug("deauthenticate $mac using RADIUS Disconnect-Request deauth method");
    return $self->radiusDisconnect($mac);
}

=head2 bouncePort

Bounce the port with a RADIUS CoA-Request carrying Extreme-Dynamic-Config = PORTBOUNCE,
the EAP sessions of the port are kept

=cut

sub bouncePort {
    my ($self, $ifIndex) = @_;
    my $logger = $self->logger;
    my $id = $self->{_id};
    if (!$self->isProductionMode()) {
        $logger->info("Switch not in production mode... we won't perform port bounce");
        return $TRUE;
    }

    if (!$self->hasRadiusSecret()) {
        $logger->warn("Unable to perform RADIUS CoA-Request on $id: RADIUS Shared Secret not configured");
        return;
    }

    # The CoA-Request identifies the port by the MAC address of an endpoint
    my @locationlog = locationlog_view_open_switchport_no_VoIP($id, $ifIndex);
    my $mac = $locationlog[0]->{'mac'};
    if (!$mac) {
        @locationlog = locationlog_view_open_switchport_only_VoIP($id, $ifIndex);
        $mac = $locationlog[0]->{'mac'};
    }

    if (!$mac) {
        $logger->info("Can't find MAC address in the locationlog... we won't perform port bounce");
        return $FALSE;
    }

    my $send_to = $self->{'_ip'};
    if (defined($self->{'_controllerIp'}) && $self->{'_controllerIp'} ne '') {
        $send_to = $self->{'_controllerIp'};
    }

    $mac = uc($mac);
    $mac =~ s/:/-/g;
    my $response;
    try {
        my $connection_info = $self->radius_deauth_connection_info($send_to);
        $response = $self->handleRadiusCoa(
            $connection_info,
            {
                'Calling-Station-Id' => $mac,
                'NAS-IP-Address'     => $send_to,
            },
            [ { vendor => 'Extreme', attribute => $DYNAMIC_CONFIG, value => 'PORTBOUNCE' } ],
        );
    } catch {
        chomp;
        $logger->warn("Unable to perform RADIUS CoA-Request: $_");
        $logger->error("Wrong RADIUS secret or unreachable network device...") if ($_ =~ /^Timeout/);
    };
    return if (!defined($response));

    return $TRUE if ($response->{'Code'} eq 'CoA-ACK');

    $logger->warn(
        "Unable to perform RADIUS CoA-Request on $id."
        . ( defined($response->{'Code'}) ? " $response->{'Code'}" : 'no RADIUS code' ) . ' received'
        . ( defined($response->{'Error-Cause'}) ? " with Error-Cause: $response->{'Error-Cause'}." : '' )
    );
    return;
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
