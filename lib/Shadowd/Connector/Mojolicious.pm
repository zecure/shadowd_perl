package Shadowd::Connector::Mojolicious;

use strict;

use base 'Shadowd::Connector';

=head1 NAME

Shadowd::Connector::Mojolicious - Shadow Daemon connector for Mojolicious applications

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
	my ($class, $query) = @_;

	my $self = $class->SUPER::new;
	$self->{'_query'} = $query;

	# Mojolicious supports cookies with shared names, so first we have to get all unique names.
	foreach my $cookie (@{$self->{'_query'}->req->cookies}) {
		$self->{'_cookies'}->{$cookie->name} = 1;
	}

	return $self;
}

=head2 gather_input

=cut

sub gather_input {
	my ($self) = @_;

	$self->{'_input'} = {};

	foreach my $key ($self->{'_query'}->param) {
		my $path = $self->{'_query'}->req->method . '|' . $self->escape_key($key);
		my @values;

		# Mojolicious 5 has separate methods to get input with the same name.
		if ($self->{'_query'}->can('every_param')) {
			@values = @{$self->{'_query'}->every_param($key)};
		} else {
			@values = $self->{'_query'}->param($key);
		}

		if ($#values > 0){
			for my $index (0 .. $#values) {
				$self->{'_input'}->{$path . '|' . $index} = $values[$index];
			}
		} else {
			$self->{'_input'}->{$path} = $values[0];
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
				$self->{'_input'}->{'COOKIE|' . $self->escape_key($key) . '|' . $index} = $values[$index];
			}
		} else {
			$self->{'_input'}->{'COOKIE|' . $self->escape_key($key)} = $values[0];
		}
	}

	my $headers = $self->{'_query'}->req->headers->to_hash;

	foreach my $key (keys %$headers) {
		$self->{'_input'}->{'SERVER|' . $self->escape_key($key)} = $headers->{$key};
	}
}

=head2 defuse_input

=cut

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
		my @path_split = $self->split_path($path);

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
				my @values;

				if ($self->{'_query'}->can('every_param')) {
					@values = @{$self->{'_query'}->every_param($key)};
				} else {
					@values = $self->{'_query'}->param($key);
				}

				$values[$path_split[2]] = '';
				$self->{'_query'}->req->param($key, @values);
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

=head2 get_client_ip

=cut

sub get_client_ip {
	my ($self) = @_;

	return $self->{'_query'}->tx->remote_address;
}

=head2 get_caller

=cut

sub get_caller {
	my ($self) = @_;

	return $self->{'_query'}->req->url->path->to_string;
}

=head2 error

=cut

sub error {
	my ($self) = @_;

	$self->{'_query'}->render(data => '<h1>500 Internal Server Error</h1>', status => 500);
}

1;
