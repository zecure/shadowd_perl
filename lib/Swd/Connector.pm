# Shadow Daemon -- Web Application Firewall
#
#   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
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

use constant {
	SHADOWD_CONNECTOR_VERSION        => '1.0.0-perl',
	SHADOWD_CONNECTOR_CONFIG         => '/etc/shadowd/connectors.ini',
	SHADOWD_CONNECTOR_CONFIG_SECTION => 'shadowd_perl',
	CONFIG_REQUIRED                  => 1,
	STATUS_OK                        => 1,
	STATUS_BAD_REQUEST               => 2,
	STATUS_BAD_SIGNATURE             => 3,
	STATUS_BAD_JSON                  => 4,
	STATUS_ATTACK                    => 5
};

sub _get_client_ip: Abstract;
sub _get_caller: Abstract;
sub _error: Abstract;
sub get_input: Abstract;
sub defuse_input: Abstract;

sub new {
	my ($class) = @_;

	my $self = {
		'_config'         => undef,
		'_config_file'    => undef,
		'_config_section' => undef,
		'_connection'     => undef,
		'_client_ip'      => undef,
		'_caller'         => undef
	};

	bless $self, $class;
	return $self;
}

sub _init_config {
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
	my ($self, $key, $required) = @_;

	if (!$self->{'_config'}->exists($self->{'_config_section'}, $key)) {
		if ($required) {
			die($key . ' in config missing');
		}

		return 0;
	}

	return $self->{'_config'}->val($self->{'_config_section'}, $key);
}

sub _init_connection {
	my ($self, $host, $port, $ssl) = @_;

	if ($ssl) {
		$self->{'_connection'} = IO::Socket::SSL->new(
			PeerHost        => $host,
			PeerPort        => $port,
			SSL_verify_mode => SSL_VERIFY_PEER,
			SSL_ca_file     => $ssl
		) or die('network error (ssl): ' . $!);
	} else {
		$self->{'_connection'} = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port
		) or die('network error: ' . $!);
	}

	# Send immediately.
	$self->{'_connection'}->autoflush(1);
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

sub remove_ignored {
	my ($self, $input, $file) = @_;

	if (!$file) {
		return $input;
	}

	open my $handler, $file or die('could not open ignore file: ' . $!);

	while (my $line = <$handler>) {
		chomp($line);

		if ($line =~ /(.+?)(\s+)(.+)/) {
			if ($3 ne $self->{'_caller'}) {
				next;
			}

			if (defined $input->{$1}) {
				delete $input->{$1};
			}
		} else {
			if (defined $input->{$line}) {
				delete $input->{$line};
			}
		}
	}

	close $handler;

	return $input;
}

sub send_input {
	my ($self, $profile, $key, $input) = @_;

	my %input_data = (
		'version'   => SHADOWD_CONNECTOR_VERSION,
		'client_ip' => $self->{'_client_ip'},
		'caller'    => $self->{'_caller'},
		'input'     => $input
	);

	my $connection = $self->{'_connection'};

	my $json = encode_json(\%input_data);
	print $connection $profile . "\n" . hmac_hex('SHA256', $key, $json) . "\n" . $json . "\n";

	my $response = <$connection>;
	my $output_data = decode_json($response);

	switch ($output_data->{'status'}) {
		case STATUS_OK            { return 0; }
		case STATUS_BAD_REQUEST   { die('bad request'); }
		case STATUS_BAD_SIGNATURE { die('bad signature'); }
		case STATUS_BAD_JSON      { die('bad json'); }
		case STATUS_ATTACK        { return $output_data->{'threats'}; }
		else                      { die('processing error'); }
	}
}

sub _log {
	my ($self, $message) = @_;

	open my $handler, '>>' . $self->{'_log'} or die('could not open log file: ' . $!);
	print $handler $message;
	close $handler;
}

sub start {
	my ($self) = @_;

	eval {
		$self->_init_config;

		$self->{'_log'} = ($self->get_config('log') || '/var/log/shadowd.log');
		$self->{'_client_ip'} = $self->_get_client_ip;
		$self->{'_caller'} = $self->_get_caller;

		my $input = $self->remove_ignored(
			$self->get_input,
			$self->get_config('ignore')
		);

		$self->_init_connection(
			($self->get_config('host') || '127.0.0.1'),
			($self->get_config('port') || '9115'),
			$self->get_config('ssl')
		);

		my $threats = $self->send_input(
			$self->get_config('profile', CONFIG_REQUIRED),
			$self->get_config('key', CONFIG_REQUIRED),
			$input
		);

		close $self->{'_connection'};

		if (!$self->get_config('observe') && $threats) {
			$self->defuse_input($threats);
		}

		if ($self->get_config('debug') && $threats) {
			$self->_log('shadowd: removed threat from client: ' . $self->{'_client_ip'} . "\n");
		}
	};

	if ($@ && !$self->get_config('observe')) {
		if ($self->get_config('debug')) {
			$self->_log($@);
		}

		$self->_error;

		return undef;
	}

	return 1;
}

1;
