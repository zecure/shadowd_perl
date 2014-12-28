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

package Swd::Connector;

use strict;

use CGI;
use JSON;
use Switch;
use Config::IniFiles;
use IO::Socket;
use IO::Socket::SSL;
use Crypt::Mac::HMAC qw(hmac_hex);
use URI::Encode qw(uri_encode);

use constant {
	SHADOWD_CONNECTOR_VERSION        => '0.0.1-perl',
	SHADOWD_CONNECTOR_CONFIG         => '/etc/shadowd/connectors.ini',
	SHADOWD_CONNECTOR_CONFIG_SECTION => 'shadowd_perl',
	CONFIG_REQUIRED                  => 1,
	STATUS_OK                        => 1,
	STATUS_BAD_REQUEST               => 2,
	STATUS_BAD_SIGNATURE             => 3,
	STATUS_BAD_JSON                  => 4,
	STATUS_ATTACK                    => 5
};

my ($query, $config, $section);

sub _init_config {
	my $file;

	if (defined $ENV{'SHADOWD_CONNECTOR_CONFIG'}) {
		$file = $ENV{'SHADOWD_CONNECTOR_CONFIG'};
	} else {
		$file = SHADOWD_CONNECTOR_CONFIG;
	}

	$config = Config::IniFiles->new(-file => $file);

	if (!$config) {
		die('config error');
	}

	if (defined $ENV{'SHADOWD_CONNECTOR_CONFIG_SECTION'}) {
		$section = $ENV{'SHADOWD_CONNECTOR_CONFIG_SECTION'};
	} else {
		$section = SHADOWD_CONNECTOR_CONFIG_SECTION;
	}
}

sub _get_config {
	my ($key, $required) = @_;

	if (!$config->exists($section, $key)) {
		if ($required) {
			die($key . ' in config missing');
		}

		return 0;
	}

	return $config->val($section, $key);
}

sub _escape_key {
	my ($key) = @_;

	$key =~ s/\\/\\\\/g;
	$key =~ s/\|/\\|/g;

	return $key;
}

sub _unescape_key {
	my ($key) = @_;

	$key =~ s/\\\\/\\/g;
	$key =~ s/\\\|/|/g;

	return $key;
}

sub _get_input {
	my $method = $query->request_method();

	my %input;

	foreach my $key ($query->param()) {
		my @value = $query->param($key);

		if ($#value > 0){
			for my $index (0 .. $#value) {
				$input{$method . '|' . _escape_key($key) . '|' . $index} = $value[$index];
			}
		} else {
			$input{$method . '|' . _escape_key($key)} = $value[0];
		}
	}

	foreach my $key ($query->cookie()) {
		$input{'COOKIE|' . _escape_key($key)} = $query->cookie($key);
	}

	foreach my $key ($query->http()) {
		$input{'SERVER|' . _escape_key($key)} = $query->http($key);
	}

	return \%input;
}

sub _remove_ignored {
	my ($input, $file, $caller) = @_;

	if (!$file) {
		return $input;
	}

	open my $handler, $file or die("could not open ignore file: " . $!);

	while (my $line = <$handler>) {
		chomp($line);

		if ($line =~ /(.+?)(\s+)(.+)/) {
			if ($3 ne $caller) {
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

sub _defuse_input {
	my ($threats) = @_;

	my %cookies;
	foreach my $cookie ($query->cookie()) {
		$cookies{$cookie} = $query->cookie($cookie);
	}

	foreach my $path (@{$threats}) {
		my @path_split = split(/\\.(*SKIP)(*FAIL)|\|/s, $path);

		if ($#path_split < 1) {
			next;
		}

		my $key = _unescape_key($path_split[1]);

		if ($path_split[0] eq 'SERVER') {
			$ENV{$key} = '';
		} elsif ($path_split[0] eq 'COOKIE') {
			delete $cookies{$key};
		} else {
			if ($#path_split == 1) {
				$query->param($key, '');
			} else {
				my @array = $query->param($key);
				$array[$path_split[2]] = '';
				$query->param($key, @array);
			}
		}
	}

	# Save the changes for the CGI module.
	$query->save_request();

	# Overwrite the query string in the env in case that the target does not use CGI.
	$ENV{'QUERY_STRING'} = $query->query_string;

	if ($query->cookie()) {
		my $cookie_string = '';

		foreach my $cookie (keys %cookies) {
			$cookie_string .= uri_encode($cookie) . '=' . uri_encode($cookies{$cookie}) . ';';
		}

		# Remove last semicolon.
		chop($cookie_string);

		# Overwrite the cookie string.
		$ENV{'HTTP_COOKIE'} = $cookie_string;
	}
}

sub _init_connection {
	my ($host, $port, $ssl) = @_;

	my $connection;

	if ($ssl) {
		$connection = IO::Socket::SSL->new(
			PeerHost        => $host,
			PeerPort        => $port,
			SSL_verify_mode => SSL_VERIFY_PEER,
			SSL_ca_file     => $ssl
		) or die("network error (ssl): " . $!);
	} else {
		$connection = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port
		) or die("network error: " . $!);
	}

	# Send immediately.
	$connection->autoflush(1);

	return $connection;
}

sub _send_connection {
	my ($connection, $profile, $key, $input, $client_ip, $caller) = @_;

	my %input_data = (
		'version'   => SHADOWD_CONNECTOR_VERSION,
		'client_ip' => $client_ip,
		'caller'    => $caller,
		'input'     => $input
	);

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

BEGIN {
	eval {
		$query = CGI->new;

		_init_config();

		my $client_ip = (_get_config('client_ip') ? $ENV{_get_config('client_ip')} : $ENV{'REMOTE_ADDR'});
		my $caller = (_get_config('caller') ? $ENV{_get_config('caller')} : $ENV{'SCRIPT_FILENAME'});

		my $connection = _init_connection(
			(_get_config('host') || '127.0.0.1'),
			(_get_config('port') || '9115'),
			_get_config('ssl')
		);

		my $input = _remove_ignored(
			_get_input(),
			_get_config('ignore'),
			$caller
		);

		my $threats = _send_connection(
			$connection,
			_get_config('profile', CONFIG_REQUIRED),
			_get_config('key', CONFIG_REQUIRED),
			$input,
			$client_ip,
			$caller
		);

		close $connection;

		if (!_get_config('observe') && $threats) {
			_defuse_input($threats);
		}
	};

	if ($@) {
		if (!_get_config('observe')) {
			print $query->header(-status => '500 Internal Server Error');
			print '<h1>500 Internal Server Error</h1>';

			if (_get_config('debug')) {
				print $@;
			}

			exit;
		}
	}
}

1;
