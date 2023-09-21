package CrowdSec::Client;

use strict;
use Date::Parse;
use HTTP::Request::Common;
use JSON;
use LWP::UserAgent;
use Moo;
use POSIX "strftime";

our $VERSION = '0.01';

has machineId => ( is => 'ro' );

has password => ( is => 'ro' );

has token => ( is => 'rw' );

has tokenVal => ( is => 'rw' );

has strictSsl => ( is => 'ro', default => 1, );

has baseUrl => ( is => 'ro' );

has userAgent => ( is => 'ro', default => sub { return LWP::UserAgent->new } );

has autoLogin => ( is => 'ro' );

has error => ( is => 'rw' );

sub login {
    my ($self) = @_;
    my $exit = 0;
    return 1 if $self->tokenIsvalid;
    foreach my $k (qw(machineId password baseUrl)) {
        unless ( $self->{$k} ) {
            $self->error("Missing parameter: $k");
        }
    }
    exit $exit if $exit;
    my $request = POST(
        $self->baseUrl . '/v1/watchers/login',
        Content_Type => 'application/json',
        Content      => JSON::to_json(
            {
                machine_id => $self->machineId,
                password   => $self->password,
                scenarios  => [],
            }
        )
    );
    my $response = $self->userAgent->request($request);
    if ( $response->is_success ) {
        eval {
            my $tmp = JSON::from_json( $response->content );
            use Data::Dumper;
            $self->token( $tmp->{token} );
            $self->tokenVal( str2time( $tmp->{expire} ) );
        };
        if ($@) {
            $self->error("Bad response content from CrowdSec server: $@");
            return 0;
        }
        if ( !$self->token and !$self->tokenVal ) {
            $self->error(
                "Missing token and expire fields in CrowdSec response: "
                  . $response->content );
        }
        return 1;
    }
    else {
        $self->error(
            "Bad response from CrowdSec server: " . $response->status_line );
        return 0;
    }
}

sub banIp {
    my ( $self, $prm ) = @_;
    unless ( $prm and ref $prm ) {
        $self->error("parameter should be a hashref");
        return 0;
    }
    unless ( $prm->{ip} ) {
        $self->error("Missing IP");
        return 0;
    }
    if ( $self->autoLogin ) {
        unless ( $self->login ) {
            return 0;
        }
    }
    unless ( $self->token ) {
        $self->error("No valid token");
        return 0;
    }
    $self->error("DEBUG $self->{token}");
    $prm->{reason} ||= 'Banned by CrowdSec::Client';
    my $stamp    = strftime "%Y-%m-%dT%H:%M:%SZ", gmtime(time);
    my $decision = [
        {
            capacity   => 0,
            created_at => $stamp,
            decisions  => [
                {
                    duration => '4h',
                    origin   => 'LLNG',
                    scenario => $prm->{reason},
                    scope    => 'Ip',
                    type     => 'ban',
                    value    => $prm->{ip}
                }
            ],
            events           => [],
            events_count     => 1,
            labels           => undef,
            leakspeed        => '0',
            message          => $prm->{reason},
            scenario         => $prm->{reason},
            scenario_hash    => '',
            scenario_version => '',
            simulated        => JSON::false,
            source           => {
                ip    => $prm->{ip},
                scope => 'Ip',
                value => $prm->{ip},
            },
            start_at => $stamp,
            stop_at  => $stamp,
        }
    ];
    my $request = POST(
        $self->baseUrl . '/v1/alerts',
        Authorization => 'Bearer ' . $self->token,
        Content_Type  => 'application/json',
        Content       => JSON::to_json($decision),
    );
    my $response = $self->userAgent->request($request);
    if ( $response->is_success ) {
        my $response_content = $response->content;
        print "Réponse du serveur : $response_content\n";
        return 1;
    }
    else {
        print "Échec de la requête : " . $response->status_line . "\n";
        return 0;
    }
}

sub tokenIsvalid {
    my ($self) = @_;
    return ( $self->tokenVal and ( $self->tokenVal > time ) );
}

1;
__END__

=head1 NAME

CrowdSec::Client - CrowdSec client

=head1 SYNOPSIS

  use CrowdSec::Client;
  my $client = CrowdSec::Client->new({
    machineId => "myid",
    password  => "mypass",
    baseUrl   => "http://127.0.0.1:8080",
    autoLogin => 1;
  });
  $client->banIp({
    ip       => '1.2.3.4',
    duration => '5h',            # default 4h
    reason   => 'Ban by my app', # default: 'Banned by CrowdSec::Client'
  }) or die( $client->error );

=head1 DESCRIPTION

CrowdSec::Client is a simple CrowdSec Watcher. It permits to ban an IP

=head1 SEE ALSO

L<https://crowdsec.net/>

=head1 AUTHOR

Xavier Guimard <xguimard@linagora.mu>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2023 by Linagora <https://linagora.com>

License: AGPL-3.0 (see LICENSE file)

=cut
