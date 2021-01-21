#!/usr/bin/perl -W

$| = 1;
use strict;
use Creatures::C3::PRAY;
use Test;

my $pray = Creatures::C3::PRAY->new();
my @files = glob("$ENV{HOME}/.dockingstation/My\\ Agents/*");
@files    = (@files, glob("$ENV{HOME}/.dockingstation/My\\ Creatures/*")); 

plan test => (scalar @files) * 3;

undef $/;

foreach my $file (@files) {
	my $data;
	open(FILE, "< $file") or die "Can't open ${file}: $!";	
	$data = <FILE>;
	close(FILE);

	# Check that we can get something from the file
	$pray->decode(\$data);
	ok(scalar @{$pray->{files_byid}});
	
	# Check that we can uncompress something, and the length matches
	my $not_ok = 0;
	foreach my $f (@{$pray->{files_byid}}) {
		my $dummy = "";

		eval {
			$dummy = $pray->uncompress_file($f, keep_compressed_data => 1);
		};
		print STDERR $@ if ($@);

	        $not_ok = 1 unless $f->{uncompressed_len} == length($dummy);
	}
	
	ok($not_ok, 0);

	my $enc = $pray->encode();
	ok ($enc eq $data);
	
	#ok(1);
}

# vim: ts=4 syntax=perl
