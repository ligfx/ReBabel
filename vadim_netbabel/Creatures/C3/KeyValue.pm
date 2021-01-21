#!/usr/bin/perl -w

package Creatures::C3::KeyValue;
use strict;

BEGIN {
	use Exporter   ();
	our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

	# The following must be all on one line
	$VERSION = do { my @r = (q$Revision: 1.3 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

	@ISA         = qw(Exporter);
	@EXPORT      = qw(&kv_to_hash &hash_to_kv);
	%EXPORT_TAGS = ( );

	# your exported package globals go here,
	# as well as any optionally exported functions
	@EXPORT_OK   = ( );
}

our @EXPORT_OK;

sub kv_to_hash {
	my $kv = shift;
	my $off = 0;
	my %ret;
	
	my $pairs = unpack('L', substr($kv, $off, 4)); $off+=4;

	#$off = 4;
	while ($off < length($kv)) {
		my $klen   = unpack('L', substr($kv, $off, 4)); $off+=4;
		my $key    = substr($kv, $off, $klen)         ; $off += $klen;
		my $tlen   = unpack('L', substr($kv, $off + 4, 4));

		my ($vlen, $value);

		#if ($tlen <= 255) {
		#	$value = unpack('L', substr($kv, $off, 4)); $off+=4;
		#} else {		
			$vlen   = unpack('L', substr($kv, $off, 4)); $off+=4;
			$value  = substr($kv, $off, $vlen)         ; $off += $vlen;
		#}
		
		$ret{$key} = $value;
		#warn "KL: $klen VL: $vlen";
		#warn "K: $key, V: $value";

	#	$got_pairs++;
	}

	return %ret;
}

sub hash_to_kv {
	my %hash = @_;
	my $ret;

	$ret = pack('L', scalar keys %hash);

	foreach my $key (keys %hash) {
		$ret .= pack('L', length($key));
		$ret .= $key;
		$ret .= pack('L', length($hash{$key}));
		$ret .= $hash{$key};
	}

	return $ret;
}

1;

=head1 NAME

Creatures::C3::KeyValue - Creatures Key/Value parser

=head1 SYNOPSIS

 #!/usr/bin/perl -w
 use Creatures::C3::KeyValue;
 my $kv;
 my %hash = kv_to_hash(<STDIN>);
 foreach my $key (keys %hash) {
 	print "$key\t$hash{$key}\n";
 }
 
 $kv = hash_to_kv(%hash);

=head1 DESCRIPTION

Some files and Docking Station messages use this format to store key/value
pairs. This module converts this data into a Perl hash and back for easier
use. To use it, you have to have a few things in mind, however:

* This module requires you to skip the first 4 bytes of the data that seem
to be used as a type field. In order for this module to work the string has
to start with the key/value count. 

* The key/value count is currently ignored while converting to a hash, but
still will be generated correctly when converting to KV.

* The module will not generate the 4 bytes mentioned above, you have to
generate them yourself if needed.

=head1 FUNCTIONS

=head2 kv_to_hash(I<$kv>)

Converts binary KV data stored in I<$kv> into a hash. Have in mind that you
need to skip the 4 bytes mentioned above in order for this to work.

NOTE: The key/value pair count is currently ignored, although it still has
to be present.

=head2 hash_to_kv(I<%hash>)

Converts I<%hash> into binary KV data.

=cut

# vim: ts=4
