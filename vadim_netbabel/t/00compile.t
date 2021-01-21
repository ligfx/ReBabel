#!/usr/bin/perl -w
use Test;
my @files = `find . -name '*.pm' -or -name '*.pl'`;
@files = (@files, glob("t/*"));

plan test => scalar @files;

foreach $file (@files) {
	chomp $file;
	$ret = `perl -W -c '$file' 2>&1`;
	chomp $ret;
	ok($ret, '/.*syntax OK$/');
}

# vim: ts=4 syntax=perl
