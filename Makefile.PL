#!/usr/bin/perl

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

use strict;

use ExtUtils::MakeMaker qw(WriteMakefile);

my %prereq = (
	'CGI'                 => 0,
	'JSON'                => 0,
	'Switch'              => 0,
	'Config::IniFiles'    => 0,
	'IO::Socket'          => 0,
	'IO::Socket::SSL'     => 0,
	'Crypt::Mac::HMAC'    => 0,
	'URI::Encode'         => 0,
	'Attribute::Abstract' => 0,
	'POSIX'               => 0
);

WriteMakefile(
	NAME         => 'Shadowd::Connector',
	VERSION_FROM => 'lib/Shadowd/Connector.pm',
	PREREQ_PM    => \%prereq,
	AUTHOR       => 'Hendrik Buchwald <hb@zecure.org>',
	ABSTRACT     => 'Perl connector for the Shadow Daemon web application firewall',
);
