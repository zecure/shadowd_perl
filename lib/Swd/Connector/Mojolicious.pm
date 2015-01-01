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

package Swd::Connector::Mojolicious 0.01;

use strict;

use base 'Swd::Connector';

sub new {
	my ($class, $query) = @_;

	my $self = $class->SUPER::new;
	$self->{'_query'} = $query;

	# Mojolicious supports cookies with shared names, so first we have to get all unique names.
	foreach my $cookie (@{$self->{'_query'}->req->cookies}) {
		$self->{'_cookies'}->{$cookie->name} = 1;
	}

	return $self;
}

sub get_input {
	my ($self) = @_;

	my %input;

	foreach my $key ($self->{'_query'}->param) {
		my @values;

		# Mojolicious 5 has separate methods to get input with the same name.
		if ($self->{'_query'}->can('every_param')) {
			@values = @{$self->{'_query'}->every_param($key)};
		} else {
			@values = $self->{'_query'}->param($key);
		}

		if ($#values > 0){
			for my $index (0 .. $#values) {
				$input{$self->{'_query'}->req->method . '|' . $self->escape_key($key) . '|' . $index} = $values[$index];
			}
		} else {
			$input{$self->{'_query'}->req->method . '|' . $self->escape_key($key)} = $values[0];
		}
	}

	foreach my $key (keys %{$self->{'_cookies'}}) {
		my @values;

		if ($self->{'_query'}->can('every_cookie')) {
			@values = @{$self->{'_query'}->every_cookie($key)};
		} else {
			@values = $self->{'_query'}->cookie($key);
		}

		if ($#values > 0){
			for my $index (0 .. $#values) {
				$input{'COOKIE|' . $self->escape_key($key) . '|' . $index} = $values[$index];
			}
		} else {
			$input{'COOKIE|' . $self->escape_key($key)} = $values[0];
		}
	}

	my $headers = $self->{'_query'}->req->headers->to_hash;

	foreach my $key (keys %$headers) {
		$input{'SERVER|' . $self->escape_key($key)} = $headers->{$key};
	}

	return \%input;
}

sub defuse_input {
	my ($self, $threats) = @_;

	my %cookies;

	foreach my $key (keys %{$self->{'_cookies'}}) {
		my @values;

		if ($self->{'_query'}->can('every_cookie')) {
			@values = @{$self->{'_query'}->every_cookie($key)};
		} else {
			@values = $self->{'_query'}->cookie($key);
		}

		$cookies{$key} = \@values;
	}

	foreach my $path (@{$threats}) {
		my @path_split = split(/\\.(*SKIP)(*FAIL)|\|/s, $path);

		if ($#path_split < 1) {
			next;
		}

		my $key = $self->unescape_key($path_split[1]);

		if ($path_split[0] eq 'SERVER') {
			$self->{'_query'}->req->headers->header($key, '');
		} elsif ($path_split[0] eq 'COOKIE') {
			if ($#path_split == 1) {
				$cookies{$key} = [''];
			} else {
				my $array = $cookies{$key};
				$array->[$path_split[2]] = '';
				$cookies{$key} = $array;
			}
		} else {
			if ($#path_split == 1) {
				$self->{'_query'}->req->param($key, '');
			} else {
				my @array = $self->{'_query'}->req->param($key);
				$array[$path_split[2]] = '';
				$self->{'_query'}->req->param($key, @array);
			}
		}
	}

	if ($self->{'_query'}->req->headers->cookie) {
		my $cookie_string = '';

		# Cookie handling in Mojolicious is very strange. No encoding.
		foreach my $key (keys %cookies) {
			foreach my $value (@{$cookies{$key}}) {
				$cookie_string .= $key . '=' . $value . ';';
			}
		}

		# Remove last semicolon.
		chop($cookie_string);

		# Overwrite the cookie string.
		$self->{'_query'}->req->headers->cookie($cookie_string);
	}
}

sub _get_client_ip {
	my ($self) = @_;

	return $self->{'_query'}->tx->remote_address;
}

sub _get_caller {
	my ($self) = @_;

	return $self->{'_query'}->req->url->path->to_string;
}

sub _error {
	my ($self, $message) = @_;

	my $body = '<h1>500 Internal Server Error</h1>';

	if ($message) {
		$body .= $message;
	}

	$self->{'_query'}->render(data => $body, status => 500);
}

1;
