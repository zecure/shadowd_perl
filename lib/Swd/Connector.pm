# Shadow Daemon -- Web Application Firewall
#
#   Copyright (C) 2014-2015 Hendrik Buchwald <hb@zecure.org>
#
# This file is part of Shadow Daemon. Shadow Daemon is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package Swd::Connector 1.00;

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

sub get_client_ip: Abstract;
sub get_caller: Abstract;
sub gather_input: Abstract;
sub defuse_input: Abstract;
sub error: Abstract;

sub new {
	my ($class) = @_;
	my $self = {};

	bless $self, $class;
	return $self;
}

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

sub get_input {
	my ($self) = @_;

	return $self->{'_input'}
}

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

sub sign {
	my ($self, $key, $json) = @_;

	return hmac_hex('SHA256', $key, $json);
}

sub log {
	my ($self, $message) = @_;

	my $file = $self->get_config('log', 0, '/var/log/shadowd.log');
	open my $handler, '>>' . $file or die('could not open log file: ' . $!);

	my $datetime = strftime('%Y-%m-%d %H:%M:%S', localtime);
	print $handler $datetime . "\t" . $message;

	close $handler;
}

sub escape_key {
	my ($self, $key) = @_;

	$key =~ s/\\/\\\\/g;
	$key =~ s/\|/\\|/g;

	return $key;
}

sub unescape_key {
	my ($self, $key) = @_;

	$key =~ s/\\\\/\\/g;
	$key =~ s/\\\|/|/g;

	return $key;
}

sub split_path {
	my ($self, $path) = @_;

	return split(/\\.(*SKIP)(*FAIL)|\|/s, $path);
}

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

1;
