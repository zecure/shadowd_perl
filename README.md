![Logo](https://shadowd.zecure.org/img/logo_small.png)

[![Build Status](https://github.com/zecure/shadowd_perl/actions/workflows/analyze.yml/badge.svg)](https://github.com/zecure/shadowd_perl/actions/workflows/analyze.yml)

**Shadow Daemon** is a *web application firewall* that intercepts requests at application-level.
This repository contains a component of Shadow Daemon to connect Python applications with the [shadowd](https://github.com/zecure/shadowd) server.

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
You can install the modules with CPAN:

    cpan -i Shadowd::Connector

It is also possible to clone this repository and install the modules manually:

    perl Makefile.PL
    make
    make install

You also have to create a configuration file. You can copy *misc/examples/connectors.ini* to */etc/shadowd/connectors.ini*.
The example configuration is annotated and should be self-explanatory.

## CGI
To protect CGI applications you simply have to load the module:

    use Shadowd::Connector::CGI;

This can be automated by executing Perl scripts with:

    perl -mShadowd::Connector::CGI

## Mojolicious
Mojolicious applications require a small modification. It is necessary to create a hook to intercept requests:

    use Shadowd::Connector::Mojolicious;
    
    sub startup {
      my $app = shift;
    
      $app->hook(before_dispatch => sub {
        my $self = shift;
        return Shadowd::Connector::Mojolicious->new($self)->start();
      });

      # ...
    }

## Mojolicious::Lite
Mojolicious::Lite applications require a small change as well:

    use Shadowd::Connector::Mojolicious;
    
    under sub {
      my $self = shift;
      return Shadowd::Connector::Mojolicious->new($self)->start();
    };

The connector is only executed if the request matches a route.
