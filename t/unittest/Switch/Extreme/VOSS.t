#!/usr/bin/perl

=head1 NAME

VOSS

=head1 DESCRIPTION

unit test for pf::Switch::Extreme::VOSS

=cut

use strict;
use warnings;
#
BEGIN {
    #include test libs
    use lib qw(/usr/local/pf/t);
    #Module for overriding configuration paths
    use setup_test_config;
}

use Test::More tests => 15;
use pf::Switch::Extreme::VOSS;
use pf::Switch::constants;
use pf::config qw($WIRED_802_1X $WIRED_MAC_AUTH);

#This test will running last
use Test::NoWarnings;

sub switch {
    my (%args) = @_;
    return pf::Switch::Extreme::VOSS->new({
        id => '10.0.0.8',
        ip => '10.0.0.8',
        mode => 'production',
        radiusSecret => 'secret',
        VlanMap => 'Y',
        RoleMap => 'Y',
        AccessListMap => 'Y',
        roles => { staff => '0:10020' },
        %args,
    });
}

sub reply {
    my ($switch, %args) = @_;
    my (undef, %reply) = @{ $switch->returnRadiusAccessAccept({ vlan => 20, user_role => 'staff', unfiltered => 'Y', %args }) };
    return \%reply;
}

is_deeply(
    reply(switch(RoleMap => 'N')),
    { 'Extreme-Dynamic-Client-Assignments' => 'pv=20,ev=0' },
    "the VLAN is returned in Extreme-Dynamic-Client-Assignments"
);

is_deeply(
    reply(switch(VlanMap => 'N')),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020' },
    "the role is returned as a Fabric Attach binding"
);

my $features = "Extreme-Dynamic-Config = DHCPSNOOP\nExtreme-Dynamic-Config = DAI\nExtreme-Dynamic-Config = IPSG\n";
is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { staff => $features })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020', 'Extreme-Dynamic-Config' => ['DHCPSNOOP', 'DAI', 'IPSG'] },
    "the access list lines of the role are returned, one attribute per line"
);

is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { staff => "Fabric-Attach-VLAN-ISID = 30:10030" })),
    { 'Fabric-Attach-VLAN-ISID' => ['0:10020', '30:10030'] },
    "an access list line adds a value to an attribute of the reply"
);

is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { guest => $features })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020' },
    "the access list of another role is not returned"
);

is_deeply(
    reply(switch(VlanMap => 'N', AccessListMap => 'N', access_lists => { staff => $features })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020' },
    "the access lists are not returned when Role by Access List is disabled"
);

is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { staff => "Extreme-Dynamic-Config = DHCPSNOOP\nExtreme-Dynamic-Config = IPSG" })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020', 'Extreme-Dynamic-Config' => 'DHCPSNOOP' },
    "IPSG without DAI is not returned"
);

is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { staff => "Extreme-Dynamic-Config = IPSG" })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020' },
    "IPSG alone is not returned"
);

is_deeply(
    reply(switch(VlanMap => 'N', access_lists => { staff => "# comment\n\npermit ip any any\nLab-Unknown-Attribute = 1\nExtreme-Dynamic-Config = BPDU" })),
    { 'Fabric-Attach-VLAN-ISID' => '0:10020', 'Extreme-Dynamic-Config' => 'BPDU' },
    "comments, empty lines, ACLs and unknown attributes are ignored"
);

is_deeply(
    [ (switch()->parseRequest({ 'User-Name' => '00-11-22-33-44-55', 'NAS-Port' => 1001 }))[2] ],
    [ '00:11:22:33:44:55' ],
    "the MAC address is taken from the User-Name without Calling-Station-Id"
);

is_deeply(
    [ (switch()->parseRequest({ 'User-Name' => 'bob', 'Calling-Station-Id' => '00-11-22-33-44-66' }))[2] ],
    [ '00:11:22:33:44:66' ],
    "the MAC address is taken from the Calling-Station-Id"
);

is(
    (switch()->wiredeauthTechniques(undef, $WIRED_MAC_AUTH))[1],
    'deauthenticateMacRadius',
    "MAC authentication sessions are deauthenticated with a Disconnect-Request"
);

is(
    (switch()->wiredeauthTechniques(undef, $WIRED_802_1X))[1],
    'deauthenticateMacRadius',
    "802.1X sessions are deauthenticated with a Disconnect-Request"
);

{
    my ($attributes, $vsa);
    no warnings qw(redefine once);
    local *pf::Switch::Extreme::VOSS::locationlog_view_open_switchport_no_VoIP = sub { return { mac => '00:11:22:33:44:55' } };
    local *pf::Switch::radius_deauth_connection_info = sub { return {} };
    local *pf::Switch::handleRadiusCoa = sub {
        my ($self, $connection_info, $attributes_ref, $vsa_ref) = @_;
        ($attributes, $vsa) = ($attributes_ref, $vsa_ref);
        return { Code => 'CoA-ACK' };
    };
    switch()->bouncePort(1001);
    is_deeply(
        [ $attributes->{'Calling-Station-Id'}, $vsa ],
        [ '00-11-22-33-44-55', [ { vendor => 'Extreme', attribute => 'Extreme-Dynamic-Config', value => 'PORTBOUNCE' } ] ],
        "the port bounce is a CoA-Request with Extreme-Dynamic-Config = PORTBOUNCE"
    );
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
