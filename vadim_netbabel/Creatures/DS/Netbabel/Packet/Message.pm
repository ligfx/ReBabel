#!/usr/bin/perl -w
##########################################################################
# Creatures::DS::Netbabel::Packet
##########################################################################
# Author:      $Author: vadim $
# Date:        $Date: 2003/05/03 12:03:00 $
# Revision:    $Revision: 1.9 $
# Description: Base packet class. It contains the basic functionality
#              needed to determine the type of a packet, and provides
#              the base methods and features.
#

package     Creatures::DS::Netbabel::Packet::Message;
use base qw(Creatures::DS::Netbabel::Packet);
use constant HEADER_LENGTH => 0x28; # Netbabel header length

# Default values
use constant UNKNOWN1 => 0x000000eb; # eb or zero
use constant UNKNOWN2 => 0x000a0001; # 000a or zero
use constant UNKNOWN3 => 0x00000000; # always zero
use constant UNKNOWN4 => 0x00000000; # always zero
use constant UNKNOWN5 => 0x00000000; # zero or cccc
use constant UNKNOWN6 => 0x00000000; # Seems to be always zero
use constant UNKNOWN7 => 0x00000001; # always 1
use constant UNKNOWN8 => 0x0000000c; # always 0c
use constant UNKNOWN9 => "\0" x UNKNOWN8;


=head1 NAME

Creatures::DS::Netbabel::Message - Netbabel message packet parser

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

Sets/returns the packet type. This class should always return 'message'

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
	foreach my $func (qw(has_receiver data_len data_len2 receiver_uid
	                     receiver_hid sender_uid sender_hid mesg_len
						 header_len mesg_start sdr_uid unknown1 unknown2
						 unknown3 unknown4 unknown5 unknown6 unknown7
						 unknown8 unknown9)) {
		*{$func} = sub {
			my ($self,$arg) = @_;
		    return $self->{$private}->{$func} unless defined $arg;
			return $self->{$private}->{$func} = $arg;
		}
	}
}

# The following must be all on one line
my $VERSION = do { my @r = (q$Revision: 1.9 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

# This is used to avoid namespace conflicts. Each of my classes stores
# its variables under the package name, for example: 
# $self->{Creatures::DS::Netbabel::Packet}->{var}. This ensures that
# the classes that inherit from it won't accidentally overwrite anything.
my $private = __PACKAGE__;

my %has_receiver     = (0x00 => 0, 0x284b5240 => 1);
my %has_receiver_rev = reverse %has_receiver;


=head1 METHODS

=head2 new(I<$packet>)

Creates a new object, decoding the packet in I<$packet> if specified. This is
equivalent to calling new() with no arguments and then calling 
$obj->decode(I<$packet>). 

=cut

sub new {
	my ($proto, $mod_dir) = @_;
	my $class = ref($proto) || $proto;
	my $self  = $class->SUPER::new();
	$self->{$private} = {};
	my $priv  = $self->{$private};
	$priv->{unknown1} = UNKNOWN1;
	$priv->{unknown2} = UNKNOWN2;
	$priv->{unknown3} = UNKNOWN3;
	$priv->{unknown4} = UNKNOWN4;
	$priv->{unknown5} = UNKNOWN5;
	$priv->{unknown6} = UNKNOWN6;
	$priv->{unknown7} = UNKNOWN7;
	$priv->{unknown8} = UNKNOWN8;
	$priv->{unknown9} = UNKNOWN9;
	$priv->{sdr_uid}  = 0;	
	    		
	bless($self, $class);	
	return $self;
}

=head2 packet_length()

Returns the length of the raw packet data in bytes. As with get_data() this
could be inaccurate if encode() wasn't called after making changes.

=cut

=head2 decode(I<$data>)

Decodes a packet contained in $data. If the use_warnings setting is set then
any invalid values detected in the packet will produce a warning. Attempts to
encode a packet that was not decoded correctly will also fail, and the
original values will be preserved in the failed places.

=cut

sub decode {
	my $self = shift;
	my $priv = $self->{$private};
	my $data = shift; #$priv->{data};
	my $hlen = HEADER_LENGTH; 
	my $mstart;
	
	$priv->{packet} = $data if defined $data;

	#warn "Parsing";
	$self->SUPER::decode($data);

    # Zero the failure count, it will be incremented by dec if something
	# doesn't work.
	
	$priv->{error_count} = 0;

	$priv->{has_receiver} = $self->dec('has_receiver', 0x04      , 4, 'L', \%has_receiver);
	$priv->{unknown1}     = $self->dec('unknown1'    , 0x08		 , 4, 'L');
	$priv->{sdr_uid}      = $self->dec('sdr_uid'     , 0x0c      , 4, 'L');
	$priv->{unknown2}     = $self->dec('unknown2'    , 0x10      , 4, 'L');
	$priv->{unknown3}     = $self->dec('unknown3'    , 0x14      , 4, 'L');
	$priv->{data_len}     = $self->dec('data_len'    , 0x18      , 4, 'L');
	$priv->{unknown4}     = $self->dec('unknown4'    , 0x1c      , 4, 'L');
	

	if ($priv->{has_receiver} != 0) {
		$priv->{receiver_uid} = $self->dec('receiver_uid', 0x20      , 4, 'L');
		$priv->{receiver_hid} = $self->dec('receiver_hid', 0x24      , 2, 'S');
	} else {
		# Incoming accept/reject/requests don't have a receiver ID, so
		# the header is 8 bytes smaller.
		$priv->{receiver_uid} = undef;
		$priv->{receiver_hid} = undef;
		$hlen -= 8;
	}

	$priv->{unknown5}     = $self->dec('unknown5'    , 0x26      , 2, 'S');	
	$priv->{data_len2}    = $self->dec('data_len2'   , $hlen     , 4, 'L');
	$priv->{sender_hid}   = $self->dec('sender_hid'  , $hlen+0x04, 2, 'S');
	$priv->{sender_uid}   = $self->dec('sender_uid'  , $hlen+0x08, 4, 'L');
	$priv->{mesg_len}     = $self->dec('mesg_len'    , $hlen+0x0c, 4, 'L');
	$priv->{unknown6}     = $self->dec('unknown6'    , $hlen+0x10, 4, 'L');
	$priv->{unknown7}     = $self->dec('unknown7'    , $hlen+0x14, 4, 'L');	
	$priv->{unknown8}     = $self->dec('unknown8'    , $hlen+0x18, 2, 'S');
	$priv->{unknown9}     = $self->dec('unknown9'    , $hlen+0x1a,10, 'a*');
	
	if($priv->{data_len2} != $priv->{data_len}) {
		warn "Data lengths don't match";
	}

	$mstart = $self->packet_length() - $priv->{mesg_len}; # Offset of the 16 bytes before PRAY
#	warn "PRAY at " . ($mstart+12) . ", " . ($priv->{mesg_len} - 12) . " bytes";
	$priv->{PRAY}         = $self->dec('PRAY'        , $mstart+12, $priv->{mesg_len}-12, 'a*');

	# Share some useful bits of info
	$priv->{header_len} = $hlen;   # Length of Netbabel header
	$priv->{mesg_start} = $mstart; # Offset of 16 bytes before PRAY
	
	
	
	return 1 if $priv->{error_count} == 0;
}


sub encode {
	my $self = shift;
	my $priv = $self->{$private};
	my $ret;
	my $hlen = HEADER_LENGTH;
	my $pl;
	my $filler;

	
	# Recalculate header size
	$hlen -= 0x08 if ($priv->{has_receiver} == 0);
	
	# Recalculate length fields
	$priv->{mesg_len}  = length($priv->{PRAY}) + 12;
	$priv->{data_len}  = $priv->{mesg_len}  + 24;
	$priv->{data_len2} = $priv->{data_len};

	# Fill packet with zeroes
	$filler = "\0" x $self->packet_length();
	
	$self->enc('filler'      , $filler              , 0x00, length($filler), 'a*'); 
	$self->SUPER::encode();
	$self->enc('has_receiver', $priv->{has_receiver}, 0x04, 4, 'L', \%has_receiver_rev);
	$self->enc('unknown1'    , $priv->{unknown1}    , 0x08, 4, 'L');
	$self->enc('uid?'        , $priv->{sdr_uid}     , 0x0c, 4, 'L');
	$self->enc('unknown2'    , $priv->{unknown2}    , 0x10, 4, 'L');
	$self->enc('unknown3'    , $priv->{unknown3}    , 0x14, 4, 'L');
	$self->enc('data_len'    , $priv->{data_len}    , 0x18, 4, 'L');
	$self->enc('unknown4'    , $priv->{unknown4}    , 0x1c, 4, 'L');
	
	
	if ($priv->{has_receiver} != 0) {
		$self->enc('receiver_uid', $priv->{receiver_uid}, 0x20, 4, 'L');
		$self->enc('receiver_hid', $priv->{receiver_hid}, 0x24, 2, 'S');
	}
	
	$self->enc('unknown5'    , $priv->{unknown5}    , 0x26      , 2  , 'S');
	
	$pl = length($priv->{PRAY});
	$self->enc('data_len2'  , $priv->{data_len2}    , $hlen     ,   4, 'L');
	$self->enc('sender_hid' , $priv->{sender_hid}   , $hlen+0x04,   2, 'S');
	$self->enc('sender_uid' , $priv->{sender_uid}   , $hlen+0x08,   4, 'L');
	$self->enc('mesg_len'   , $priv->{mesg_len}     , $hlen+0x0c,   4, 'L');
	$self->enc('unknown6'   , $priv->{unknown6}     , $hlen+0x10,   4, 'L');
	$self->enc('unknown7'   , $priv->{unknown7}     , $hlen+0x14,   4, 'L');
	$self->enc('unknown8'   , $priv->{unknown8}     , $hlen+0x18,   2, 'S');
	$self->enc('unknown9'   , $priv->{unknown9}     , $hlen+0x1a,  10, 'a*');
	$self->enc('PRAY'       , $priv->{PRAY}         , $hlen+0x24, $pl, 'a*');
	
	
}

sub min_header_length {
	# If there's no receiver field the packet will be 8 bytes shorter,
	# but PRAY will add up so that the maximum header length always 
	# works here.
	return HEADER_LENGTH;
}

sub packet_length {
	my $self = shift;
	my $priv = $self->{$private};
	my $ret = HEADER_LENGTH;

	$ret += $priv->{data_len};
	$ret -=8 if $priv->{has_receiver} == 0;

	return $ret;	
}

sub PRAY {
	my ($self, $arg) = @_;
	my $priv=$self->{$private};

	if( not defined $arg ) {
		if (not defined $priv->{PRAY}) {
			$priv->{PRAY} = substr(${$self->packet()}, $priv->{mesg_start}+16);
		}
		
		return $priv->{PRAY};
	}

	$priv->{PRAY} = $arg;
	$self->mesg_len(length($arg));
	$self->data_len($self->mesg_len() + HEADER_LENGTH + 2); # XXX Not correct!
	$self->data_len2($self->data_len());
	
	
#$self->enc('PRAY', $priv->{mesg_start}+16, length($arg), 'a*');
#	$priv->
	
	#die "Setting PRAY data not implemented yet";
}

1;
##########################################################################
# Change Log
##########################################################################
# $Log: Message.pm,v $
# Revision 1.9  2003/05/03 12:03:00  vadim
# Fixed data length checking, removed debug output
#
# Revision 1.8  2003/04/29 00:44:44  vadim
# added default value for sdr_uid field
#
# Revision 1.7  2003/04/29 00:30:42  vadim
# Message encoding mostly done, at least it can re-encode a decoded one.
# PRAY encoding finished (seems to work at least)
# KeyValue kind of working (seems to have trouble with numerical values)
# Packet.pm tweaked a bit to allow omiting the length
# Netbabel now has a make_message function.
# parsedump improved to dump more information and check message encoding.
#
# Revision 1.6  2003/04/27 01:51:38  vadim
# Beginning of PRAY support in Message parser
#
# Revision 1.5  2003/04/20 01:51:49  vadim
# Deleted the part of the log that didn't correspond to this module
#
# Revision 1.4  2003/04/14 17:41:25  vadim
# Changed decode to work on a scalar reference instead. This allows to decode
# the header once, fetch the rest of the data and read the data from the
# packet directly without a second decode call.
#
# Revision 1.3  2003/04/14 15:28:37  vadim
# Added packet_length and min_header_length methods
#
# Revision 1.2  2003/04/07 00:20:44  vadim
# Fixed bug that caused incorrect decoding of the second data length.
#
# Revision 1.1  2003/04/06 21:40:55  vadim
# Message packet parser added, already has most basic functionality, but
# can't write to packets yet.


# Settings for vim
# vim: ts=4
