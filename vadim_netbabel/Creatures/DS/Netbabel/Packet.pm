#!/usr/bin/perl -w
##########################################################################
# Creatures::DS::Netbabel::Packet
##########################################################################
# Author:      $Author: vadim $
# Date:        $Date: 2003/05/10 19:31:30 $
# Revision:    $Revision: 1.13 $
# Description: Base packet class. It contains the basic functionality
#              needed to determine the type of a packet, and provides
#              the base methods and features.
#

package Creatures::DS::Netbabel::Packet;

=head1 NAME

Creatures::DS::Netbabel::Packet - Base netbabel packet parser

=head1 SYNOPSIS

  #!/usr/bin/perl -w
  use Creatures::DS::Netbabel::Packet;
  my $packet = new Creatures::DS::Netbabel::Packet;
  $packet->decode($data);
  print $packet->length();

=head1 GET/SET METHODS

This module contains several functions that work in the same way: calling the
function with an argument changes a setting, and calling it with no argument
returns the current setting.

When calling the function with an argument the return value is currently
the passed argument. This may change in the future.

=head2 type(I<$type>)

Sets/returns the packet type. Currently the following types are known:

 * auth: Login packet.
 * message: Chats, messages, and creatures.
 * user_online and user_online2: Probably sent when an user goes online.
 * user_offline: Thought to be sent when an user goes offline.
 * keepalive: Currently unknown, but suspected to be a keepalive.
 * unknown1: No idea.

=head2 packet(I<$packet>)

Gets/sets the raw packet data to the string provided in $data. At this time
this doesn't produce a call to decode() or encode(). When using encode()
all the known parts of the packet will be overwritten. You could use this
to modify unknown or reserved parts, but using enc() could be a better idea.

NOTE: At this time whether a call to decode()/encode() will be produced
or not is still undecided, so don't rely on it.

=head2 use_warnings(I<$warn>)

Gets/sets the use_warnings setting. When it is set the module will generate
warnings if something doesn't look right. In any case, error codes will be
returned.

=head2 error_count(I<$count>)

Gets/sets the error count. This is updated during decode() and encode() and
contains the number of fields that couldn't be decoded/encoded correctly. 

While setting this value is currently possible, it does not have any effect,
since it is cleared by the functions that use it.

=cut

use Carp;
use strict;

BEGIN {
	# This really odd thing is brought to you by Dylan! Actually, it's pretty
	# cool. This code automatically creates the functions to get/set fields,
	# which is nice since they all have the same code. 
	
	my $private = __PACKAGE__;
	
	no strict 'refs';
	foreach my $func (qw(type raw_type packet use_warnings error_count)) {
		*{$func} = sub {
			my ($self,$arg) = @_;
		    return $self->{$private}->{$func} unless defined $arg;
			return $self->{$private}->{$func} = $arg;
		}
	}
}

# The following must be all on one line
my $VERSION = do { my @r = (q$Revision: 1.13 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

# This is used to avoid namespace conflicts. Each of my classes stores
# its variables under the package name, for example: 
# $self->{Creatures::DS::Netbabel::Packet}->{var}. This ensures that
# the classes that inherit from it won't accidentally overwrite anything.
my $private = __PACKAGE__;

# Some hashes to lookup values
my %packet_types     = (0x09 => 'message',
                        0x10 => 'login1',       # unknown, sent during login
                        0x13 => 'login2',       # same as above.
                        0x0a => 'auth_reply',   # Reply to auth
                        0x0d => 'user_online',  ##The meaning of these three is
                        0x0e => 'user_offline', ##unclear.
                        0x0f => 'user_online2', ##
                        0x18 => 'keepalive',    # No idea, actually
                        0x21 => 'unknown1',     # Begins with 21 03 hex.
                        0x25 => 'auth');        # Username, password.

my %packet_types_rev = reverse %packet_types;

#my %has_receiver     = (0x00 => 0, 0x42524b28 => 1);
#my %has_receiver_rev = reverse %has_receiver;


=head1 METHODS

=head2 new(I<\$packet>)

Creates a new object, decoding the packet in I<$packet> if specified. This is
equivalent to calling new() with no arguments and then calling 
$obj->decode(I<$packet>). 

=cut

sub new {
	my ($proto, $mod_dir) = @_;
	my $class = ref($proto) || $proto;
	my $self  = {};
	my $pk = "";
	$self->{$private} = {};
	my $priv  = $self->{$private};
	$priv->{packet} = \$pk;	
	    		
	bless($self, $class);	
	return $self;
}

#=head2 packet_length()
#
#Returns the length of the raw packet data in bytes. As with get_data() this
#could be inaccurate if encode() wasn't called after making changes.
#
#=cut
#
#sub packet_length() {
#	my $self = shift;
#	my $priv = $self->{$private};
#
#	return length($priv->{packet});
#}

=head2 decode(I<\$data>)

Decodes a packet contained in $data. If the use_warnings setting is set then
any invalid values detected in the packet will produce a warning. Attempts to
encode a packet that was not decoded correctly will also fail, and the
original values will be preserved in the failed places.

=cut

sub decode {
	my $self = shift;
	my $priv = $self->{$private};
	my $data = shift;

	if (defined $data) {
		croak("Scalar reference required") if not ref($data) eq 'SCALAR';
		$priv->{packet} = $data;
	}

	# Zero the failure count, it will be incremented by dec if something
	# doesn't work.
	$priv->{error_count} = 0;
	
	($priv->{raw_type}, $priv->{type}) = $self->dec('type', 0x00, 1, 'C', \%packet_types);
	
	return 1 if $priv->{error_count} == 0;
}

=head2 encode()

Encodes a packet. If a packet was decoded then it will reuse the string
used for decoding and overwrite it. Otherwise it will create a new one
that you'll have to get by calling $obj->packet().

=cut

sub encode {
	my $self = shift;
	my $priv = $self->{$private};

	if (not defined $priv->{packet}) {
		$priv->{packet} = chr(0);
	}
	
	$priv->{error_count} = 0;
	$self->enc('type', $priv->{type}, 0x00, 1, 'C', \%packet_types_rev);

	return 1 if $priv->{error_count} == 0;
}


=head2 dec(I<$what>, I<$offset>, I<$len>, I<$template>, I<$hashref>)

This function is mostly for internal use. It unpacks the $len bytes at offset
$offset with template $template, and checks that the resulting value
corresponds to a key in $hashref if $hashref is defined.

If the key is found it returns its value.

If the key is not found it returns undef, and emits a warning if use_warnings
is set, using $what as the description of the field that didn't decode.

=cut

sub dec {
	my $self = shift;
	my ($what,$offset,$len,$pack,$hash) = @_;
	my $priv = $self->{$private};

	confess("No packet data") unless defined $priv->{packet};

	if($offset+$len > length(${$priv->{packet}})) {
		if ($priv->{use_warnings}) {
			warn "Packet too short or internal error. Tried to access offset $offset with length $len".
			     " in a packet that is " . length(${$priv->{packet}}) . " bytes long.";
		}
		$priv->{error_count}++;
		return undef;
	}
	my $val  = unpack($pack, substr(${$priv->{packet}},$offset,$len));

	return ($val, $val)          if not defined $hash;
	return ($val, $hash->{$val}) if (exists($hash->{$val}));

	if ($priv->{use_warnings}) {
		my $hex = "0x".sprintf("%.2x", $val);
		warn "Invalid value $val ($hex) for field '$what' (Offset $offset, len $len)\n".
		     "Valid values: ".join(" ", keys %$hash);
	}

	# Increment failure count
	$priv->{error_count}++;
	return ($val, undef);		
}

=head2 enc(I<$what>, I<$value>, I<$offset>, I<$len>, I<$template>, I<$hashref>)

This function is mostly for internal use. It's the reverse of dec(). It packs
$value with template $template, and replaces $len bytes at $offset in the
packet with the result.

If $hashref is defined then it looks up $value in it, and if it exists uses
the key's value to pass it to pack. If the key isn't found then the packet
is left unchanged, and enc() returns undef, and produces a warning if 
use_warnings is set.

=cut

sub enc {
	my $self = shift;
	my($what,$value,$offset,$len,$pack,$hash) = @_;
	my $priv = $self->{$private};
	my $val;

	confess("Tried encoding an undefined value") if not defined $value;
    confess("Tries encoding at an undefined offset") if not defined $offset;

	if (defined $hash) {
		if(exists $hash->{$value}) {
			$val = $hash->{$value};
		} else {
			if($priv->{use_warnings}) {
				warn "Invalid value '$val' for field '$what' (Offset $offset, len $len)\n".
				     "Valid values: ".join(" ", keys %$hash);
			}

			# Increment failure count
			$priv->{error_count}++;
			return undef;
		}
	} else {
		$val = $value;
	}

#	warn "E: $offset $len " . length(${$priv->{packet}});
	$len = length($val) if (not defined $len);
	
	eval {
		substr(${$priv->{packet}}, $offset, $len) = pack($pack, $val);
	};

	if($@) {
		croak("P: $what $offset $len " . $@);
	}
}

=head2 packet_length()

This function returns the length of the full packet. With the exception
of this base class it has to always return the full packet size, including
all unknown, reserved and deprecated parts.

In this class it always returns 1, because this is the base class that 
provides the base methods and is not capable of parsing any packets on
its own.

This method MUST be implemented correctly for all the packet types that
might ocurr. Otherwise networking will break after the program receives a 
packet with a length it can't determine.

NOTE: This method may fail and return undef if not enough data is available.
To check whether enough data has arrived to determine the length you must
perform these steps:

 * Obtain at least one byte of data to determine packet type.
 * Call that type's parser min_header_length() method.
 * Once you have min_header_length() bytes you can call packet_length()

=cut

sub packet_length {
	# Doesn't really matter what data we have, in this class we only
	# consider the first byte relevant, so here the packet is always
	# one byte long. In classes that inherit from this one the length
	# has to be the real one, or it will break networked apps that 
	# use it.
	return 1;
}

=head2 min_header_length() 

This method returns the minimum amount of bytes the packet's header can use.
It MUST be enough to determine the full packet's length.

In this base class it will always return 1.
Any classes that inherit from this class MUST reimplement this method.

=cut

sub min_header_length {
	# This class only parses the first byte of the header, so we return
	# a 1, although this doesn't match the actual value. A packet class
	# MUST redefine this method.
	return 1;
}
1;
##########################################################################
# Change Log
##########################################################################
# $Log: Packet.pm,v $
# Revision 1.13  2003/05/10 19:31:30  vadim
# Some debugging added for unknown packets
#
# Revision 1.12  2003/04/29 00:30:42  vadim
# Message encoding mostly done, at least it can re-encode a decoded one.
# PRAY encoding finished (seems to work at least)
# KeyValue kind of working (seems to have trouble with numerical values)
# Packet.pm tweaked a bit to allow omiting the length
# Netbabel now has a make_message function.
# parsedump improved to dump more information and check message encoding.
#
# Revision 1.11  2003/04/20 01:54:14  vadim
# Added login1 and login2 support.
# Replaced tabs with spaces in packet type list to avoid screwing up formatting.
#
# Revision 1.10  2003/04/15 01:00:32  vadim
# Added proper encoding support, with some debugging.
#
# Revision 1.9  2003/04/14 17:41:25  vadim
# Changed decode to work on a scalar reference instead. This allows to decode
# the header once, fetch the rest of the data and read the data from the
# packet directly without a second decode call.
#
# Revision 1.8  2003/04/14 15:32:00  vadim
# Fixed syntax error
#
# Revision 1.7  2003/04/14 15:28:37  vadim
# Added packet_length and min_header_length methods
#
# Revision 1.6  2003/04/14 15:03:36  vadim
# Now checks if the offset passed to dec() is inside the packet, and emits
# a warning if it's not.
#
# Added packet_length() method.
#
# Revision 1.5  2003/04/08 16:29:28  vadim
# Just some minor comment changes. No real code differences.
#
# Revision 1.4  2003/04/05 18:53:41  vadim
# Added auth_reply packet type.
# Added parsedump.pl testing script.
#
# Revision 1.3  2003/04/05 18:23:30  vadim
# POD documentation updated.
#
# Revision 1.2  2003/04/05 15:54:42  vadim
# Added Dylan's automatic get/set function generator.
# The basic design of the class is pretty much done, and it works too.
#
# Revision 1.1  2003/04/03 20:24:32  vadim
# Added the initial dsd source tree.
#

# Settings for vim
# vim: ts=4
