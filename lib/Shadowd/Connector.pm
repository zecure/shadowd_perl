package Shadowd::Connector;

use strict;

use JSON;
use Switch;
use Config::IniFiles;
use IO::Socket;
use IO::Socket::SSL;
use Crypt::Mac::HMAC qw(hmac_hex);
use Attribute::Abstract;
use POSIX qw(strftime);

use constant {
	SHADOWD_CONNECTOR_VERSION        => '1.0.0-perl',
	SHADOWD_CONNECTOR_CONFIG         => '/etc/shadowd/connectors.ini',
	SHADOWD_CONNECTOR_CONFIG_SECTION => 'shadowd_perl',
	STATUS_OK                        => 1,
	STATUS_BAD_REQUEST               => 2,
	STATUS_BAD_SIGNATURE             => 3,
	STATUS_BAD_JSON                  => 4,
	STATUS_ATTACK                    => 5
};

=head1 NAME

Shadowd::Connector - Shadow Daemon connector base

=head1 VERSION

Version 1.00

=cut

our $VERSION = '1.00';

=head1 SYNOPSIS

Quick summary of what the module does.

=cut

=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
	my ($class) = @_;
	my $self = {};

	bless $self, $class;
	return $self;
}

=head2 get_client_ip

=cut

sub get_client_ip: Abstract;

=head2 get_caller

=cut

sub get_caller: Abstract;

=head2 gather_input

=cut

sub gather_input: Abstract;

=head2 defuse_input

=cut

sub defuse_input: Abstract;

=head2 error

=cut

sub error: Abstract;

=head2 init_config

=cut

sub init_config {
	my ($self) = @_;

	if (defined $ENV{'SHADOWD_CONNECTOR_CONFIG'}) {
		$self->{'_config_file'} = $ENV{'SHADOWD_CONNECTOR_CONFIG'};
	} else {
		$self->{'_config_file'} = SHADOWD_CONNECTOR_CONFIG;
	}

	$self->{'_config'} = Config::IniFiles->new(-file => $self->{'_config_file'});

	if (!$self->{'_config'}) {
		die('config error');
	}

	if (defined $ENV{'SHADOWD_CONNECTOR_CONFIG_SECTION'}) {
		$self->{'_config_section'} = $ENV{'SHADOWD_CONNECTOR_CONFIG_SECTION'};
	} else {
		$self->{'_config_section'} = SHADOWD_CONNECTOR_CONFIG_SECTION;
	}
}

=head2 get_config

=cut

sub get_config {
	my ($self, $key, $required, $default) = @_;

	if (!$self->{'_config'}->exists($self->{'_config_section'}, $key)) {
		if ($required) {
			die($key . ' in config missing');
		} else {
			return $default;
		}
	} else {
		return $self->{'_config'}->val($self->{'_config_section'}, $key);
	}
}

=head2 get_input

=cut

sub get_input {
	my ($self) = @_;

	return $self->{'_input'}
}

=head2 remove_ignored

=cut

sub remove_ignored {
	my ($self, $file) = @_;

	local $/ = undef;
	open my $handler, $file or die('could not open ignore file: ' . $!);
	binmode $handler;

	my $content = <$handler>;
	my $json = decode_json($content);

	foreach my $entry (@$json) {
		if (!defined $entry->{'path'} && defined $entry->{'caller'}) {
			if ($self->{'_caller'} eq $entry->{'caller'}) {
				$self->{'_input'} = {};

				last;
			}
		} else {
			if (defined $entry->{'caller'}) {
				if ($self->{'_caller'} ne $entry->{'caller'}) {
					next;
				}
			}

			if (defined $entry->{'path'}) {
				delete $self->{'_input'}->{$entry->{'path'}};
			}
		}
	}

	close $handler;
}

=head2 send_input

=cut

sub send_input {
	my ($self, $host, $port, $profile, $key, $ssl) = @_;

	my $connection;

	if ($ssl) {
		$connection = IO::Socket::SSL->new(
			PeerHost        => $host,
			PeerPort        => $port,
			SSL_verify_mode => SSL_VERIFY_PEER,
			SSL_ca_file     => $ssl
		) or die('network error (ssl): ' . $!);
	} else {
		$connection = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port
		) or die('network error: ' . $!);
	}

	$connection->autoflush(1);

	my %input_data = (
		'version'   => SHADOWD_CONNECTOR_VERSION,
		'client_ip' => $self->get_client_ip,
		'caller'    => $self->get_caller,
		'input'     => $self->get_input
	);

	my $json = encode_json(\%input_data);
	print $connection $profile . "\n" . $self->sign($key, $json) . "\n" . $json . "\n";

	my $output = <$connection>;

	close $connection;

	return $self->parse_output($output);
}

=head2 parse_output

=cut

sub parse_output {
	my ($self, $output) = @_;

	my $output_data = decode_json($output);

	switch ($output_data->{'status'}) {
		case STATUS_OK            { return 0; }
		case STATUS_BAD_REQUEST   { die('bad request'); }
		case STATUS_BAD_SIGNATURE { die('bad signature'); }
		case STATUS_BAD_JSON      { die('bad json'); }
		case STATUS_ATTACK        { return $output_data->{'threats'}; }
		else                      { die('processing error'); }
	}
}

=head2 sign

=cut

sub sign {
	my ($self, $key, $json) = @_;

	return hmac_hex('SHA256', $key, $json);
}

=head2 log

=cut

sub log {
	my ($self, $message) = @_;

	my $file = $self->get_config('log', 0, '/var/log/shadowd.log');
	open my $handler, '>>' . $file or die('could not open log file: ' . $!);

	my $datetime = strftime('%Y-%m-%d %H:%M:%S', localtime);
	print $handler $datetime . "\t" . $message;

	close $handler;
}

=head2 escape_key

=cut

sub escape_key {
	my ($self, $key) = @_;

	$key =~ s/\\/\\\\/g;
	$key =~ s/\|/\\|/g;

	return $key;
}

=head2 unescape_key

=cut

sub unescape_key {
	my ($self, $key) = @_;

	$key =~ s/\\\\/\\/g;
	$key =~ s/\\\|/|/g;

	return $key;
}

=head2 split_path

=cut

sub split_path {
	my ($self, $path) = @_;

	return split(/\\.(*SKIP)(*FAIL)|\|/s, $path);
}

=head2 start

=cut

sub start {
	my ($self) = @_;

	eval {
		$self->init_config;

		$self->gather_input;

		my $ignored = $self->get_config('ignore');
		if ($ignored) {
			$self->remove_ignored($ignored);
		}

		my $threats = $self->send_input(
			$self->get_config('host', 0, '127.0.0.1'),
			$self->get_config('port', 0, '9115'),
			$self->get_config('profile', 1),
			$self->get_config('key', 1),
			$self->get_config('ssl')
		);

		if (!$self->get_config('observe') && $threats) {
			$self->defuse_input($threats);
		}

		if ($self->get_config('debug') && $threats) {
			$self->log('shadowd: removed threat from client: ' . $self->get_client_ip . "\n");
		}
	};

	if ($@) {
		if ($self->get_config('debug')) {
			$self->log($@);
		}

		unless ($self->get_config('observe')) {
			$self->error;

			return undef;
		}
	}

	return 1;
}

=head1 AUTHOR

Hendrik Buchwald, C<< <hb at zecure.org> >>

=head1 BUGS

Please report any bugs or feature requests to L<https://github.com/zecure/shadowd_perl/issues>, C<bug-shadowd-connector at rt.cpan.org>,
or through the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Shadowd-Connector>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Shadowd::Connector


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Shadowd-Connector>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Shadowd-Connector>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Shadowd-Connector>

=item * Search CPAN

L<http://search.cpan.org/dist/Shadowd-Connector/>

=back

=head1 LICENSE AND COPYRIGHT

Shadow Daemon -- Web Application Firewall

  Copyright (C) 2014-2015 Hendrik Buchwald C<< <hb at zecure.org> >>

This file is part of Shadow Daemon. Shadow Daemon is free software: you can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, version 2.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see L<http://www.gnu.org/licenses/>.

=cut

1; # End of Shadowd::Connector
