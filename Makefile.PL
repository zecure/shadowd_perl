#!/usr/bin/perl
use strict;

use ExtUtils::MakeMaker qw(WriteMakefile);

my %prereq = (
	'CGI'               => 0,
	'JSON'              => 0,
	'Switch'            => 0,
	'Config::IniFiles'  => 0,
	'IO::Socket'        => 0,
	'IO::Socket::SSL'   => 0,
	'Crypt::Mac::HMAC'  => 0,
	'URI::Encode'       => 0,
);

WriteMakefile(
	NAME         => 'Swd::Connector',
	VERSION_FROM => 'lib/Swd/Connector.pm',
	PREREQ_PM    => \%prereq,
	AUTHOR       => 'Hendrik Buchwald <hb@zecure.org>',
	ABSTRACT     => 'Perl connector for Shadow Daemon web application firewall',
);
