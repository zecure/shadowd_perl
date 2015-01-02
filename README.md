**Shadow Daemon** is a modular **web application firewall**. It prevents attacks against web applications by intercepting requests, detecting malicious user input and removing it.

This component can be used to connect Perl applications with the [background server](https://github.com/zecure/shadowd).

# Documentation
For the full documentation please refer to [shadowd.zecure.org](https://shadowd.zecure.org/).

# Installation
You can install the modules with CPAN:

    cpan -i Swd::Connector

It is also possible to clone this repository and install the modules manually:

    perl Makefile.PL
    make
    make install

## CGI
To protect CGI applications you simply have to load the module:

    use Swd::Connector::CGI;

This can be automated by executing Perl scripts with:

    perl -mSwd::Connector::CGI

## Mojolicious
Mojolicious applications require a small modification. It is necessary to create a hook to intercept requests:

    use Swd::Connector::Mojolicious;
    
    sub startup {
      my $app = shift;
    
      $app->hook(before_dispatch => sub {
        my $self = shift;
        return Swd::Connector::Mojolicious->new($self)->start();
      });

      # ...
    }

## Mojolicious::Lite
Mojolicious::Lite applications require a small change as well:

    use Swd::Connector::Mojolicious;
    
    under sub {
      my $self = shift;
      return Swd::Connector::Mojolicious->new($self)->start();
    };

The connector is only executed if the request matches a route.
