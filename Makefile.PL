#!/usr/bin/perl
use strict;

use ExtUtils::MakeMaker qw(WriteMakefile);

WriteMakefile(
	NAME               => 'Shadowd::Connector',
	VERSION_FROM       => 'lib/Shadowd/Connector.pm',
	ABSTRACT           => 'Connector for the Shadow Daemon web application firewall',
	AUTHOR             => 'Hendrik Buchwald <hb@zecure.org>',
	LICENSE            => 'GPLv2',
	CONFIGURE_REQUIRES => {
		'ExtUtils::MakeMaker' => 0,
	},
	BUILD_REQUIRES     => {
		'Test::More' => 0,
	},
	PREREQ_PM          => {
		'CGI'                 => 0,
		'JSON'                => 0,
		'Switch'              => 0,
		'Config::IniFiles'    => 0,
		'IO::Socket'          => 0,
		'IO::Socket::SSL'     => 0,
		'Crypt::Mac::HMAC'    => 0,
		'URI::Encode'         => 0,
		'Attribute::Abstract' => 0,
		'POSIX'               => 0,
	},
	dist               => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	clean              => { FILES => 'Shadowd-Connector-*' },
);
