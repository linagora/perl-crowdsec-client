# NAME

CrowdSec::Client - CrowdSec client

# SYNOPSIS

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

# DESCRIPTION

CrowdSec::Client is a simple CrowdSec Watcher. It permits to ban an IP.

## Constructor

CrowdSec::Client requires a hashref as argument with the following keys:

- **machineId** _(required)_: the watcher identifier given by Crowdsec
_(see ["Enrollment"](#enrollment))_.
- **password** _(required)_: the watcher password
- **baseUrl** _(required)_: the base URL to connect to local CrowdSec
server. Example: **http://localhost:8080**.
- **userAgent** _(optional)_: a [LWP::UserAgent](https://metacpan.org/pod/LWP%3A%3AUserAgent) object. If noone is
given, a new LWP::UserAgent will be created.
- **autoLogin**: indicates that CrowdSec::Client has to login automatically
when `banIp()` is called. Else you should call manually `login()` method.
- **strictSsl**: _(default: 1)_. If set to 0, and if **userAgent** isn't
set, the internal LWP::UserAgent will ignore SSL errors.

## Methods

### banIp()

banIp adds the given IP into decisions. Usage:

    $client->banIp( { %parameters } );

Parameters:

- **ip** _(required)_: the IP address to ban
- **duration** _(default: 4h)_: the duration of the decision
- **origin** _(default: "CrowdSec::Client")_
- **reason** _(default: "Banned by CrowdSec::Client")_
- **scenario** _(default: "Banned by CrowdSec::Client"))_
- **simulated** _(default: 0)_: if set to 1, the flag simulated is added
- **type** _(default: "ban")_

# Enrollment

# SEE ALSO

[CrowdSec](https://crowdsec.net/)

# AUTHOR

Xavier Guimard <xguimard@linagora.mu>

# COPYRIGHT AND LICENSE

Copyright (C) 2023 by [Linagora](https://linagora.com)

License: AGPL-3.0 (see LICENSE file)
