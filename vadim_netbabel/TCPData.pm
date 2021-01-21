#!/usr/bin/perl -w
use strict;
use Carp;

BEGIN {
	use Exporter   ();
	our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

	# The following must be all on one line
	$VERSION = do { my @r = (q$Revision: 1.1 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

	@ISA         = qw(Exporter);
	@EXPORT      = qw(&extract_tcp_data);
	%EXPORT_TAGS = ( );

	# your exported package globals go here,
	# as well as any optionally exported functions
	@EXPORT_OK   = ( );
}

sub extract_tcp_data {
	my ($pk, %options) = @_;
	my $byte;
	my $off;
	my $tcpoff;
	my $tcpstart;
	
	$off = 0;
	unless (defined $options{no_ethernet}) {
		# Skip ethernet header
		$off = 14;
	}

	unless (defined $options{no_ip}) {
		my $ipvr; # IP version
		my $iphl; # IP header length
		my $iptl; # IP total length
		
		$byte = get_data($pk, $off, 1);

		# Get IP version
		$ipvr = ($byte & 0b11110000);
		$ipvr = ($ipvr >> 4);

		if ($ipvr != 4) {
			return (undef, "Unknown IP version: $ipvr")
		}

		# Get header length
		$iphl = ($byte & 0b00001111);

		if ($iphl < 5) {
			return (undef, "Bad IHL: $iphl");
		}

		# Get the IP total length, and cut any
		# trailing stuff.
		$iptl = get_data($pk, $off + 2, 2);
		if (($off + $iptl) > length($pk)) {
			return (undef, "Bad Total Length: $iptl");
		}

		$pk = substr($pk, 0, $off + $iptl);

		# IHL indicates the header length in 32 bit
		# words.
		$off += ($iphl * 4);
	}

	# Skip TCP source port, dest port, seq number, and ack number
	$tcpstart = $off;
	$off     += 2 + 2 + 4 + 4;

	# Extract TCP Data Offset field
	$byte     = get_data($pk, $off, 1);
	
	$tcpoff   = ($byte & 0b11110000);
	$tcpoff   = ($tcpoff >> 4);
	
	# Skip the rest of the TCP header, the offset is in
	# 32 bit words
	$off      = $tcpstart + ($tcpoff * 4);

	# Extract TCP data
	if ($off > length($pk)) {
		confess "Trying to return bytes starting at offset $off in a ".
		        length($pk) . " bytes packet";
	}
	return substr($pk, $off);
	
}

sub get_data {
	my ($str, $offset, $len) = @_;
	my $tmp;
	
	if ( ($len + $offset) > length($str)) {
		confess "Internal error: trying to access $len bytes at offset $offset ".
		        "in a " . length($str) . " bytes packet";
	}
	
	$tmp = substr($str, $offset, $len);

	if ($len == 1) {
		return unpack('C', $tmp);
	} elsif ($len == 2) {
		return unpack('n', $tmp);
	} elsif ($len == 4) {
		return unpack('L', $tmp);
	} else {	
		confess "Internal error: Don't know how to decode $len bytes";
	}
}

1;

# vim: ts=4
