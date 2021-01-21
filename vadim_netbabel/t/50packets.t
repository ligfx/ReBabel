#!/usr/bin/perl -w
use Test;
use Carp qw(verbose);
use strict;
use Net::Pcap;
use Creatures::DS::Netbabel;
use Creatures::C3::PRAY;
use TCPData;

use constant DEBUG => 1;

$|=1;

my ($pcap, $error, $file, $np,$n,$errors,%types);
my %stats;
my $count = 0;

$np = new Creatures::DS::Netbabel;
$np->use_warnings(1) if DEBUG;

# Rather dumb way of counting packets, but stats
# don't seem to work
foreach $file (glob("*.dump")) {
	$pcap = Net::Pcap::open_offline($file, \$error);
	die "pcap: $error" if  $pcap < 0;
	
	Net::Pcap::loop($pcap, -1, sub { $count++},undef);
	Net::Pcap::close($pcap);
}

plan test => $count;

foreach $file (glob("*.dump")) {
	$pcap = Net::Pcap::open_offline($file, \$error);
	die "pcap: $error" if $pcap < 0;

	Net::Pcap::loop($pcap, -1, decode(), $np);
	Net::Pcap::close($pcap);
}


sub decode {
	my $need_bytes;
	my $buffer;

	$need_bytes = 1;
	$buffer     = "";
	
	return sub {
		my ($np, $hdr, $packet) = @_;
		my $npk;
		my $orig;
		my $error   = undef;
		my $skipped = undef;
		my $hlen;
		my $length;
		my $type;
		my $rawtype;

		$packet = extract_tcp_data($packet);

		# No data, nothing to do.
		if ($packet eq "") {
			ok(1);
			return;
		}

		$orig   = $packet;
		$buffer.=$packet;

		if (DEBUG) {
			warn "Added   " . length($packet). " bytes to   buffer, buffer is now " . length($buffer) . " bytes";
		}
		if ($need_bytes > length($buffer)) {
			warn $need_bytes - length($buffer) .  " more bytes needed" if DEBUG;
			ok(1);
#			warn "Got ". length($buffer) .", need $need_bytes";
			return;
		}
		
		($npk,$length,$hlen) = $np->decode(\$buffer);
		
		if ((not defined $npk) && defined($hlen)) {
			$need_bytes = $hlen;
			warn "Need $hlen bytes to parse header" if DEBUG;
			ok(1);
			return;
		}

		if (defined $length && ($length > length($buffer))) {
			$need_bytes = $length;
			warn "Need $length bytes to parse packet" if DEBUG;
			ok(1);
			return;
		}

#		if ($need_bytes > length($buffer)) {
#			ok(1);
#           warn "Got ". length($buffer) .", need $need_bytes";
#			return;			
#		}

#		if (defined $length && ($length > length($buffer))) {
#			$need_bytes = $length;
#			ok(1);
#			warn "Got ". length($buffer) .", need $need_bytes";
#			return;
#		}

#		$need_bytes = length($packet);
		
#		die "Not defined" unless defined $need_bytes;

		#
		#if (defined $length) {
		#	if (length($buffer) < $length) {
		#		# Message too big for one packet, get more data
		#		ok(1);
		#		return;
		#	}
		#} else {
		#	$length = length($packet);
		#}
		
		$type    = "unknown";
		#$rawtype = "unknown";
		$rawtype = sprintf("%.2x", $np->pk_rawtype());

		if (not defined $npk) {
#			warn "--- Error above from packet $n";
			$error = "misc";
			$errors++;
		} else {
			$type    = $npk->type();
			$rawtype = sprintf("%.2x", $npk->raw_type());
			
			if( defined $type) {
				$types{$type}++;
				# Write current packet to disk, so that if we die
				# we can see what went wrong.
				writefile("message.cur", $orig);

				if ($type eq 'message') {
					$npk->use_warnings(1);
#					$npk->decode();
					my $pdata = $npk->PRAY();

#					if ($pdata =~ /^PRAY/) {
#						my $pray = new Creatures::C3::PRAY;
#						$pray->decode(\$pdata);
#						my $f = $pray->{files_byid}->[0];
#						my $unc = $pray->uncompress_file($f, keep_compressed_data => 1 );
#						my $uor = $unc;
#						$pray->add_compressed_file(0, $f->{name}, $f->{type}, \$unc);
#						$unc = $pray->uncompress_file($f, keep_compressed_data => 1);
#						if ($uor ne $unc) {
#							$error = 1;
#						}
#					}
					
					if($npk->data_len() != $npk->data_len2()) {
						#warn "Data lengths don't match!";
						$error = "msg_datalen";
					}

#					$npk->encode();
#					if ($orig ne $packet) {
#						writefile("message.dec", $orig);
#						writefile("message.enc", $packet);
#						$error = 1;
#					}
					
					$npk->decode();
				} elsif ($type eq "auth") {
				} elsif ($type eq "auth_reply") {
					$npk->encode();
					$npk->decode();
#					$npk->encode();
				} elsif ($type eq "login1") {
					# Nothing yet
					$skipped = 1;
				} elsif ($type eq "login2") {
					# Nothing yet
					$skipped = 1;
				} else {
					$skipped = 1;
				}
			} else {
				warn "Unknown packet type, code $rawtype";
				writefile("packets/$n.unknown.$rawtype", $buffer);
			}
		}


		$n++;

		# Remove processed data from buffer
		if (not defined $need_bytes) {
#			$need_bytes = $length; #length($packet);
			$need_bytes = length($buffer);
		}

		$need_bytes = length($buffer);
#	warn "B: " . length($buffer) . " C: $need_bytes";
	#$buffer = substr($buffer, $need_bytes);
	
		if ((not $skipped) && $error) {
			warn "Failed on $type ticket ($n)" if DEBUG;
			writefile("packets/$n.$error.$type.$rawtype", $buffer);
		} else {
			writefile("packets/ok/$n", $buffer);
		}
	
		$buffer = substr($buffer, $need_bytes);

		if (DEBUG) {
			warn "Removed $need_bytes bytes from buffer, buffer is now ".
   	 		     length($buffer) . " bytes";
		}
		
		$need_bytes = 0;
	
		skip($skipped, $error, undef);
	}

}

sub writefile {
	my ($file, $data) = @_;
	open(FILE, "> $file") or die "Can't open ${file}: $!";
	print FILE $data;
	close(FILE);
}

# vim: ts=4 syntax=perl
