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

	my $self = $class->SUPER::new();
	$self->{'_query'} = $query;

	return $self;
}

sub get_input {
	my ($self) = @_;

	my %input;

	foreach my $key ($self->{'_query'}->param) {
		my @value = $self->{'_query'}->param($key);

		if ($#value > 0){
			for my $index (0 .. $#value) {
				$input{$self->{'_query'}->req->method . '|' . $self->escape_key($key) . '|' . $index} = $value[$index];
			}
		} else {
			$input{$self->{'_query'}->req->method . '|' . $self->escape_key($key)} = $value[0];
		}
	}

	my $headers = $self->{'_query'}->req->headers->to_hash;

	foreach my $key (keys %$headers) {
		$input{'SERVER|' . $self->escape_key($key)} = $headers->{$key};
	}

	# TODO: add cookie support

	return \%input;
}

sub defuse_input {
	my ($self, $threats) = @_;

	foreach my $path (@{$threats}) {
		my @path_split = split(/\\.(*SKIP)(*FAIL)|\|/s, $path);

		if ($#path_split < 1) {
			next;
		}

		my $key = $self->unescape_key($path_split[1]);

		if ($path_split[0] eq 'SERVER') {
			$self->{'_query'}->req->headers->header($key, '');
		} else {
			if ($#path_split == 1) {
				$self->{'_query'}->req->param($key, '');
			} else {
				my @array = $self->{'_query'}->req->param($key);
				$array[$path_split[2]] = '';
				$self->{'_query'}->req->param($key, @array);
			}
		}

		# TODO: add cookie support
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
