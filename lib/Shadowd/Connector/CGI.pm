package Shadowd::Connector::CGI;

use strict;

use base 'Shadowd::Connector';

use CGI;
use URI::Encode qw(uri_encode);

=head1 NAME

Shadowd::Connector::CGI - Shadow Daemon connector for CGI applications

=head1 VERSION

Version 1.0.0

=cut

our $VERSION = '1.0.0';

=head1 SYNOPSIS

Shadowd::Connector::CGI is the Shadow Daemon connector for Perl CGI applications. The module operates fully
automatic and only has to be loaded to start its task.

=cut

=head1 SUBROUTINES/METHODS

=head2 new

Construct an object of the class and save a CGI object as an attribute.

=cut

sub new {
	my ($class, $query) = @_;

	my $self = $class->SUPER::new;
	$self->{'_query'} = $query;

	return $self;
}

=head2 gather_input

Gather the user input from the environment that is parsed by the CGI module.

=cut

sub gather_input {
	my ($self) = @_;

	$self->{'_input'} = {};

	foreach my $key ($self->{'_query'}->param) {
		my $path = $self->{'_query'}->request_method . '|' . $self->escape_key($key);
		my @values = $self->{'_query'}->param($key);

		if ($#values > 0){
			for my $index (0 .. $#values) {
				$self->{'_input'}->{$path . '|' . $index} = $values[$index];
			}
		} else {
			$self->{'_input'}->{$path} = $values[0];
		}
	}

	foreach my $key ($self->{'_query'}->cookie) {
		$self->{'_input'}->{'COOKIE|' . $self->escape_key($key)} = $self->{'_query'}->cookie($key);
	}

	foreach my $key ($self->{'_query'}->http) {
		$self->{'_input'}->{'SERVER|' . $self->escape_key($key)} = $self->{'_query'}->http($key);
	}
}

=head2 defuse_input

Defuse dangerous input by overwriting the environment of the script.

=cut

sub defuse_input {
	my ($self, $threats) = @_;

	my %cookies;

	foreach my $cookie ($self->{'_query'}->cookie) {
		$cookies{$cookie} = $self->{'_query'}->cookie($cookie);
	}

	foreach my $path (@{$threats}) {
		my @path_split = $self->split_path($path);

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

=head2 get_client_ip

Get the ip address of the client from the environment.

=cut

sub get_client_ip {
	my ($self) = @_;

	return $ENV{$self->get_config('client_ip', 0, 'REMOTE_ADDR')};
}

=head2 get_caller

Get the caller from the environment.

=cut

sub get_caller {
	my ($self) = @_;

	return $ENV{$self->get_config('caller', 0, 'SCRIPT_FILENAME')};
}

=head2 error

Print an error message.

=cut

sub error {
	my ($self) = @_;

	print $self->{'_query'}->header(-status => '500 Internal Server Error');
	print '<h1>500 Internal Server Error</h1>';
}

BEGIN {
	my $connector = Shadowd::Connector::CGI->new(CGI->new);

	if (!$connector->start) {
		exit;
	}
}

=head1 AUTHOR

Hendrik Buchwald, C<< <hb at zecure.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-shadowd-connector at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Shadowd-Connector>.  I will be notified, and then you'll automatically
be notified of progress on your bug as I make changes.

It is also possible to report bugs via Github at L<https://github.com/zecure/shadowd_perl/issues>.

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

1; # End of Shadowd::Connector::CGI
