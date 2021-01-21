#!/usr/bin/perl -w
use Carp qw(verbose);
use strict;
use Net::Pcap;
use Creatures::DS::Netbabel;
use Creatures::C3::PRAY;

$|=1;

my ($pcap, $error, $file, $np,$n,$errors,%types);
$file = $ARGV[0] || "test.dump" ;

$np = new Creatures::DS::Netbabel;
$pcap = Net::Pcap::open_offline($file, \$error);
#$np->use_warnings(1);
die "pcap: $error" if not defined $pcap;

Net::Pcap::loop($pcap, -1, \&decode, $np);


Net::Pcap::close($pcap);

warn "Finished decoding $n packets, with $errors errors\n";

foreach my $k (keys %types) {
	warn sprintf("%-20s",$k).$types{$k}."\n";
}

sub decode {
	my ($np, $hdr, $packet) = @_;
	my $npk;
	my $orig;
	$packet = substr($packet, 54);
	$orig   = $packet;
	
	# Ignore small and large packets (norns)
	if( length($packet) > 16 && length($packet)< 1400) {
		#print "----" .length($packet)."\n$packet\n";
		($npk,undef,undef) = $np->decode(\$packet);
		
		if (not defined $npk) {
#			warn "--- Error above from packet $n";
			$errors++;
		} else {
			my $type = $npk->type();
			if( defined $type) {
				$types{$type}++;
				writefile("message.cur", $orig);
#				print "DECODING ".length($packet)." bytes\n";
				if ($type eq 'message') {
#					$npk->encode();
#					$npk->decode();
					$npk->use_warnings(1);
#					$npk->decode();
					print "--- MESSAGE ---\n";
					print "BYTES:       ".length($packet)."\n";
					print "EC:          ". $npk->error_count()."\n";
					print "Receiver:    ". $npk->has_receiver()."\n";
					print "unknown1     ". $npk->unknown1()."\n";
					print "sdr_uid:     ". $npk->sdr_uid()."\n";
					print "unknown2     ". $npk->unknown2()."\n";
					print "unknown3     ". $npk->unknown3()."\n";
					print "data_len:    ". $npk->data_len()."\n";
					print "unknown4     ". $npk->unknown4()."\n";
					print "data_len2:   ". $npk->data_len2()."\n";
					if($npk->has_receiver() != 0) {
						print "receiver_uid:". $npk->receiver_uid()."\n";
						print "receiver_hid:". $npk->receiver_hid()."\n";
					}
					print "unknown5     ". $npk->unknown5()."\n";					
					print "sender_uid:  ". $npk->sender_uid()."\n";
					print "sender_hid:  ". $npk->sender_hid()."\n";
					print "mesg_len:    ". $npk->mesg_len()."\n";
					print "unknown6     ". $npk->unknown6()."\n";
					print "unknown7     ". $npk->unknown7()."\n";
					print "unknown8     ". $npk->unknown8()."\n";
					print "unknown9     ". $npk->unknown9()."\n";
					print "header_len:  ". $npk->header_len()."\n";
					print "mesg_start:  ". $npk->mesg_start()."\n";
					print "packet_len:  ". $npk->packet_length() . "\n";
					my $pdata = $npk->PRAY();
					print "PRAY:        ". length($pdata)." bytes\n";

					if ($pdata =~ /^PRAY/) {
						my $pray = new Creatures::C3::PRAY;
						$pray->decode(\$pdata);
						my $f = $pray->{files_byid}->[0];
						my $unc = $pray->uncompress_file($f);
						my $uor = $unc;
						$pray->add_compressed_file(0, $f->{name}, $f->{type}, \$unc);
						$unc = $pray->uncompress_file($f);
						if ($uor ne $unc) {
							warn "ORIG: ".length($uor) . " NOW: ".length($unc);
							die "Compressed data doesn't match";
						}
					}
					
					if($npk->data_len() != $npk->data_len2()) {
						warn "Data lengths don't match!";
					}
					print "Encoding...\n";
					$npk->encode();
					if ($orig eq $packet) {
						print "Packets match!\n";
					} else {
						print "Packets don't match :-(\n";
						writefile("message.dec", $orig);
						writefile("message.enc", $packet);
						die "Aborted.";
					}
					print "Decoding again...\n";
					$npk->decode();
					print "Done.\n";
					#die;
				} elsif ($type eq "auth") {
					print "--- AUTH ---\n";
					print "Username:    ". $npk->username()."\n";
					print "Password:    ". $npk->password()."\n";
				} elsif ($type eq "auth_reply") {
					$npk->encode();
					$npk->decode();
					print "--- AUTH REPLY ---\n";
					print "receiver_hid:". $npk->receiver_hid()."\n";
					print "receiver_uid:". $npk->receiver_uid()."\n";
					print "server count:". $npk->server_count()."\n";

					my %servers = %{$npk->servers()};
					foreach my $s (keys %servers) {
						print "$s: ".$servers{$s}->{address}."\n";
						print "$s: ".$servers{$s}->{friendlyname}."\n";
					}
#					$npk->encode();
				}
			}
		}
	}

	$n++;
}

sub writefile {
	my ($file, $data) = @_;
	open(FILE, "> $file") or die "Can't open ${file}: $!";
	print FILE $data;
	close(FILE);
}

