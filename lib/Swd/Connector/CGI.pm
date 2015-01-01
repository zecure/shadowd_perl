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

package Swd::Connector::CGI 1.00;

use strict;

use base 'Swd::Connector';
use CGI;
use URI::Encode qw(uri_encode);

sub new {
	my ($class, $query) = @_;

	my $self = $class->SUPER::new;
	$self->{'_query'} = $query;

	return $self;
}

sub get_input {
	my ($self) = @_;

	my %input;

	foreach my $key ($self->{'_query'}->param) {
		my @values = $self->{'_query'}->param($key);

		if ($#values > 0){
			for my $index (0 .. $#values) {
				$input{$self->{'_query'}->request_method . '|' . $self->escape_key($key) . '|' . $index} = $values[$index];
			}
		} else {
			$input{$self->{'_query'}->request_method . '|' . $self->escape_key($key)} = $values[0];
		}
	}

	foreach my $key ($self->{'_query'}->cookie) {
		$input{'COOKIE|' . $self->escape_key($key)} = $self->{'_query'}->cookie($key);
	}

	foreach my $key ($self->{'_query'}->http) {
		$input{'SERVER|' . $self->escape_key($key)} = $self->{'_query'}->http($key);
	}

	return \%input;
}

sub defuse_input {
	my ($self, $threats) = @_;

	my %cookies;

	foreach my $cookie ($self->{'_query'}->cookie) {
		$cookies{$cookie} = $self->{'_query'}->cookie($cookie);
	}

	foreach my $path (@{$threats}) {
		my @path_split = split(/\\.(*SKIP)(*FAIL)|\|/s, $path);

		if ($#path_split < 1) {
			next;
		}

		my $key = $self->unescape_key($path_split[1]);

		if ($path_split[0] eq 'SERVER') {
			$ENV{$key} = '';
		} elsif ($path_split[0] eq 'COOKIE') {
			$cookies{$key} = '';
		} else {
			if ($#path_split == 1) {
				$self->{'_query'}->param($key, '');
			} else {
				my @values = $self->{'_query'}->param($key);
				$values[$path_split[2]] = '';
				$self->{'_query'}->param($key, @values);
			}
		}
	}

	# Save the changes for the CGI module.
	$self->{'_query'}->save_request;

	# Overwrite the query string in the env in case that the target does not use CGI.
	$ENV{'QUERY_STRING'} = $self->{'_query'}->query_string;

	if (defined $ENV{'HTTP_COOKIE'}) {
		my $cookie_string = '';

		foreach my $key (keys %cookies) {
			$cookie_string .= uri_encode($key) . '=' . uri_encode($cookies{$key}) . ';';
		}

		# Remove last semicolon.
		chop($cookie_string);

		# Overwrite the cookie string.
		$ENV{'HTTP_COOKIE'} = $cookie_string;
	}
}

sub _get_client_ip {
	my ($self) = @_;

	return ($self->get_config('client_ip') ? $ENV{$self->get_config('client_ip')} : $ENV{'REMOTE_ADDR'});
}

sub _get_caller {
	my ($self) = @_;

	return ($self->get_config('caller') ? $ENV{$self->get_config('caller')} : $ENV{'SCRIPT_FILENAME'});
}

sub _error {
	my ($self, $message) = @_;

	print $self->{'_query'}->header(-status => '500 Internal Server Error');
	print '<h1>500 Internal Server Error</h1>';

	if ($message) {
		print $message;
	}
}

BEGIN {
	my $connector = Swd::Connector::CGI->new(CGI->new);

	if (!$connector->start) {
		exit;
	}
}

1;
