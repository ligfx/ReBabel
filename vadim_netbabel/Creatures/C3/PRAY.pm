#!/usr/bin/perl -w

package Creatures::C3::PRAY;

use Compress::Zlib;
use Carp;
use strict;

=head1 NAME

Creatures::C3::PRAY

=head1 SYNOPSIS

 #!/usr/bin/perl -w
 use Creatures::C3::PRAY; 
 my $pray = new Creatures::C3::PRAY;
 $pray->decode(<STDIN>);
 print "Files: " . $pray->{files_byid}->[0]->{uncompressed_len};

=head1 METHODS

Object methods

=cut

BEGIN {
	# This really odd thing is brought to you by Dylan! Actually, it's pretty
	# cool. This code automatically creates the functions to get/set fields,
	# which is nice since they all have the same code.

	my $private = __PACKAGE__;

	no strict 'refs';
	foreach my $func (qw(magic)) {
		*{$func} = sub {
			my ($self,$arg) = @_;
		    return $self->{$private}->{$func} unless defined $arg;
			return $self->{$private}->{$func} = $arg;
		}
	}
}


# The following must be all on one line
my $VERSION = do { my @r = (q$Revision: 1.5 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

# This is used to avoid namespace conflicts. Each of my classes stores
# its variables under the package name, for example:
# $self->{Creatures::DS::Netbabel::Packet}->{var}. This ensures that
# the classes that inherit from it won't accidentally overwrite anything.
my $private = __PACKAGE__;

=head2 new([I<\$data>])

Creates a new Creatures::C3::PRAY object, optionally decoding the data
referenced by I<$data> if it's defined.

=cut


sub new {
	my ($proto, $data) = @_;
	my $class = ref($proto) || $proto;
	my $self = {};

	$self->{$private} = {};
	my $priv  = $self->{$private};


	bless($self, $class);
	$self->{files_byid} = [];
	$self->{files_byname} = {};
	$priv->{magic} = 'PRAY';
	$self->decode($data) if defined $data;
	
	return $self;
}

=head2 decode(I<$data>)

Decodes the data referenced by I<$data>. If the data passed to it doesn't
look like PRAY, is too short, or contains an error, this method will call
confess(). You can trap these errors with eval {}.

This function doesn't uncompress the files stored in the PRAY. Use the
uncompress_file() method to do that.

=cut

sub decode {
	my $self = shift;
	my $priv = $self->{$private};
	my $data = shift;
	
	confess "Data too short for PRAY" if (length($$data) < 0x94);
	$priv->{curr_offset} = 0; # This will be changed by get_str().
	$priv->{magic} = $self->get_str($data,4);
	$self->{files_byid}   = []; 
	$self->{files_byname} = {};

#	$self->{files} = [];
	
	confess "Data is not PRAY" unless ($priv->{magic} eq "PRAY");
	
	my $datalen = length($$data);
	my $count = 0;
	while ($priv->{curr_offset} < $datalen) {
		my $file = {};
		my $name;
		$count++;
#		warn "Parsing file $count";
		
		# Read type field, it's always an uppercase text string.
		$file->{type} = $self->get_str($data, 4);
		unless ($file->{type} =~ m/[A-Z]{4}/) {
			confess "Strange type field, file corrupt?";
		}
		
		# Read file name
		$file->{name} = $self->get_str($data, 128);
		$file->{name} =~ s/\0+$//; # Remove trailing zeroes.
#		warn "F: " . $name;
		
		# Read compressed and uncompressed length
		$file->{compressed_len}   = unpack('L', $self->get_str($data, 4));
		$file->{uncompressed_len} = unpack('L', $self->get_str($data, 4));

#		warn "C: ". $file->{compressed_len};
#		warn "U: ". $file->{uncompressed_len};
		if ($file->{compressed_len} > $file->{uncompressed_len}) {
#			confess "compressed_len > uncompressed_len, file corrupt?";
		}
		
		# No idea about this one. Seems to be always '1'
		$file->{is_compressed} = unpack('L', $self->get_str($data, 4));

		# Read the file's content into memory.
		if ($priv->{curr_offset} + $file->{compressed_len} > $datalen) {
			confess "Premature end of file, file truncated?";
		}
		$file->{data} = $self->get_str($data, $file->{compressed_len});

		# Add the ID to the array to make using foreach easier.
		$file->{id}   = scalar(@{$self->{files_byid}});
		
		# Add to the general list.
		# We keep two lists, an array that stores the files in sequence, by
		# the order they appear in the PRAY, and a hash that stores by
		# filename.
		# NOTE: $self is intentional here. This is a public hash.
		push(@{$self->{files_byid}}, $file);
		$self->{files_byname}->{$file->{name}} = $file;
	}
	
}

# Just a small function to avoid the need of keeping track of the offset
sub get_str {
	my $self = shift;
	my $priv = $self->{$private};
	my $string = shift;
	my $length = shift;
	my $ret;
	
	unless (defined $priv->{curr_offset}) {
		$priv->{curr_offset} = 0;
	}

	# We should never go out of bounds, add some checking
	# just in case.
	if($priv->{curr_offset} + $length > length($$string)) {
		confess ("Trying to read $length bytes at offset ".$priv->{curr_offset}.
		", but data is only ".length($$string)." bytes long");
	}
	
	$ret = substr($$string, $priv->{curr_offset}, $length);
	$priv->{curr_offset} += $length;
	
	return $ret;
}

=head2 encode()

Encodes the values of the object into a PRAY file. Currently this function
is very inefficent and will return the whole file as a string. 

See the note in decode().

=cut

sub encode {
	my $self = shift;
	my $priv = $self->{$private};
	my $ret;

	$ret = $priv->{magic};
	foreach my $file (@{$self->{files_byid}}) {
		$ret .= $self->file_as_binary($file);
	}
	
	return $ret;
}

=head2 uncompress_file(I<$file>, [I<%flags>])

Uncompresses I<$file> and returns the data as a string. I<$file>
must be one of the keys in the $obj->{files} hash. If it doesn't
exist then a fatal error will be generated.

I<%flags> can be used to modify the behavior. The following flags
exist:

 * keep_compressed_data: Tells the method not to free the compressed
   data after decompression. This is useful if you need to call 
   uncompress_file() more than once, or plan to encode() after calling
   uncompress_file().

=cut

sub uncompress_file {
	my ($self, $file, %flags) = @_;
	
	my $priv = $self->{$private};
	my ($i, $out, $status);

	($i, $status)   = inflateInit();
	if(ref($file) ne "HASH") {
		croak "Hash reference to the file expected";
	}

	if(not defined $file->{data} or $file->{data} eq "") {
		croak "No data to uncompress!";
	}

	return $file->{data} if ($file->{is_compressed} == 0);
	
	if (not defined $i) {
		confess "inflateInit failed with status $status";
	}

	if (defined $flags{keep_compressed_data}) {
		# Don't pass the reference to avoid inflate from deleting
		# the buffer's contents.
		my $tmp = $file->{data};
		($out, $status) = $i->inflate(\$tmp);
	} else {
		($out, $status) = $i->inflate($file->{data});
	}
	
	if (not defined $out) {
		confess "inflate failed with status $status, on $file->{name}";
	}

	return $out;
}

=head2 add_compressed_file(I<$file>, I<$type>, I<\$data>)

Adds a file with the I<$file> name, type I<$type>, and compresses
the data referenced in I<\$data>. If the file already existed in
the hash it will be overwritten. If I<$file> is undef then the new
file will be added at the bottom.

If you want to bypass compression use the add_raw_file() function,
or modify the $obj->{files_byid} and $obj->{files_byname} hashes
manually.

=cut

sub add_compressed_file {
	my $self = shift;
	my $priv = $self->{$private};
	my ($id, $name, $type, $data) = @_;
	my ($i, $out, $status);
	my $out2;

	confess "Data must be passed as a SCALAR ref" unless ref($data) eq "SCALAR";
	
	my $ulen = length($$data);
#	warn "Compressing: $$data";

	($i, $status)   = deflateInit();
	if (not defined $i) {
		confess "deflateInit failed with status $status";
	}

	($out, $status) = $i->deflate($data);
	if (not defined $out) {
		confess "deflate failed with status $status";
	}

	($out, $status) = $i->flush();
	if (not defined $out) {
		confess "flush failed with status $status";
	}
	
#	warn "Compressed data: " . length($out) . " bytes";
	$self->add_raw_file($id, $name, $type, $ulen, $out);
	
}

=head2 add_raw_file(I<$id>, I<$name>, I<$type>, I<$ulen>, I<$data>)

Adds a new file to the object, without performing compression. This
is useful if you already compressed it. If I<$id> is undef then the
file will be added at the bottom of the PRAY file. If I<$id> corresponds
a file that already exist in the PRAY file, then it will be overwritten.
Inserting files in the middle is currently not supported.

=cut


sub add_raw_file {
	my $self = shift;
	my $priv = $self->{$private};
	my ($id, $name, $type, $uncompressed_len, $data) = @_;
	my ($i, $out, $status);

	unless (defined $id) {
		$id = scalar @{$self->{files_byid}};
	}

	if ($id < 0) {
		confess "Invalid file ID: $id";
	}
	
	my $file = {};
	
	$file->{type}             = $type;
	$file->{uncompressed_len} = $uncompressed_len;
	$file->{compressed_len}   = length($data);
	$file->{is_compressed}    = 1;
	$file->{name}             = $name;
	$file->{id}               = $id;
	$file->{data}             = $data;

	$self->{files_byid}->[$id]     = $file;
	$self->{files_byname}->{$name} = $file;
}

=head2 del_file(I<$file>)

Deletes the file referenced by I<$file> from the PRAY object. This is
equivalent to undefining the entry in $obj->{files_byid} and
deleting the entry from $obj->{files_byname}. 

This function doesn't change file IDs, so if you delete a file from the
middle the IDs won't be continuous. 

=cut

sub del_file {
	my $self = shift;
	my $priv = $self->{$private};
	my ($file) = @_;

	undef  $self->{files_byid}->[$file->{id}];
	delete $self->{files_byname}->{$file->{name}};
}

=head2 file_as_binary($file) 

Returns the binary representation of a file to be written into a PRAY
file. This can be used to avoid allocating memory for the whole file
at once. For creating a PRAY file this way you have to write the magic
number first:

 print OUT $pray->magic();
 print OUT $pray->file_as_binary($pray->{files_byid}->[0]);

PRAY files don't keep a count of the files stored in them, so you can
create PRAY files by selecting several files from a large PRAY file.

NOTE: Although it's possible to write several files with the same name
into a PRAY file, it's not recommended. Only the last of the duplicates
will be accessible thorugh the files_byname hash.

=cut

sub file_as_binary {
	my $self = shift;
	my $priv = $self->{$private};
	my $file = shift;
	my $ret = "";

	unless(ref($file) eq "HASH") {
		croak "Hash reference to the file expected";
	}
	$ret .= $file->{type};
	$ret .= $file->{name} . ("\0" x (128 - length($file->{name})));
	$ret .= pack('L', $file->{compressed_len});
	$ret .= pack('L', $file->{uncompressed_len});
	$ret .= pack('L', $file->{is_compressed});
	$ret .= $file->{data};
	return $ret;
}

=head1 PUBLIC VARIABLES

After decoding the PRAY file two public variables are created, 
the $obj->{files_byid} array, and the $obj->{files_byname} hash.

Both should contain exactly the same data, but encoding is done
using $obj->{files_byid} in order to keep the same order as in
the file that was read. 

$obj->{files_byname} is provided for your convenience, and is not
read by the class. However, if you modify these variables you should
keep them both in sync to avoid bugs in your program.

Some methods in this class expect a key from one of these variables
as an argument. 

=cut


1;

##########################################################################
# Change Log
##########################################################################
# $Log: PRAY.pm,v $
# Revision 1.5  2003/05/03 12:01:47  vadim
# Removed debug output
#
# Revision 1.4  2003/04/29 17:24:38  vadim
# Found that the unknown1 field indicates use of compression, renamed to is_compressed.
# Fixed decoding of uncompressed PRAY data
# Fixed memory leak where using decode multiple times on the same object.
#
# Revision 1.3  2003/04/29 00:30:42  vadim
# Message encoding mostly done, at least it can re-encode a decoded one.
# PRAY encoding finished (seems to work at least)
# KeyValue kind of working (seems to have trouble with numerical values)
# Packet.pm tweaked a bit to allow omiting the length
# Netbabel now has a make_message function.
# parsedump improved to dump more information and check message encoding.
#
# Revision 1.2  2003/04/26 17:10:40  vadim
# PRAY class pretty much finished now. Can decode and encode correctly.
# Changed class to keep the files in an array instead of a hash to preserve
# the order in which they were in the original file (makes testing easier).
#
# Revision 1.1  2003/04/25 23:44:05  vadim
# Added PRAY parser class and test program. Both already seem to work with DS
# creatures and agents.
#
#


# Settings for vim
# vim: ts=4
