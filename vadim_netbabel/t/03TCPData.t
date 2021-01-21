#!/usr/bin/perl -w
use Test;
use Carp qw(verbose);
use strict;
use Net::Pcap;
use TCPData;

$|=1;

my ($pcap, $error, $file, $np,$errors);
my $count=0;
my $n = 0;


foreach $file (glob("*.dump")) {
	$pcap = Net::Pcap::open_offline($file, \$error);
	die "pcap: $error" if not defined $pcap;
	Net::Pcap::loop($pcap, -1, sub { $count++ },1);
	Net::Pcap::close($pcap);
}

plan test => $count;

foreach $file (glob("*.dump")) {
	$pcap = Net::Pcap::open_offline($file, \$error);
	die "pcap: $error" if not defined $pcap;
	Net::Pcap::loop($pcap, -1, \&decode,1);
	Net::Pcap::close($pcap);
}


sub decode {
	my ($np, $hdr, $packet) = @_;
	my ($dec, $error);
	my $ok = 1;

	eval {
		($dec, $error) = extract_tcp_data($packet);
	};
	
	if ($@ ne "") {
		$ok = 0;
		warn "$@";
	}
	
	if (not defined $dec) {
		$ok = 0;
		warn $error;
	}
	
	$n++;
	writefile("packets/raw/$n", $dec);
	
	ok($ok);
}

sub writefile {
	my ($file, $data) = @_;
	open(FILE, "> $file") or die "Can't open ${file}: $!";
	print FILE $data;
	close(FILE);
}

# vim: ts=4 syntax=perl
