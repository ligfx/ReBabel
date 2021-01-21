#!/usr/bin/perl -w
use Test;
use Creatures::C3::KeyValue;


my ($data, $data2);
my (%hash, %copy);
$hash{Key1} = "Value1";
$hash{Key2} = "Value2";

plan test => 3 + (scalar keys %hash);

# Test if the conversion returns something
$data = hash_to_kv(%hash);
ok($data);

# Test conversion back to hash
%copy = kv_to_hash($data);

# Make sure the keys are in the same order
my @copy_keys = sort keys %copy;
my @hash_keys = sort keys %hash;

ok((scalar @copy_keys), (scalar @hash_keys));

# Test that data matches
foreach my $key (keys %copy) {
	ok($copy{$key}, $hash{$key});
}

# Test that re-encoding works
# TODO: Since the order may be different, for now I will just
# make it check the length. Do something better later.
$data2 = hash_to_kv(%copy);
ok(length($data), length($data2));

# vim: ts=4 syntax=perl
