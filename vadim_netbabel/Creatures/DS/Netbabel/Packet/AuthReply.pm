#!/usr/bin/perl -w
##########################################################################
# Creatures::DS::Netbabel::Packet
##########################################################################
# Author:      $Author: vadim $
# Date:        $Date: 2003/04/20 01:51:18 $
# Revision:    $Revision: 1.6 $
# Description: Base packet class. It contains the basic functionality
#              needed to determine the type of a packet, and provides
#              the base methods and features.
#

package     Creatures::DS::Netbabel::Packet::AuthReply;
use base qw(Creatures::DS::Netbabel::Packet);
use constant HEADER_LENGTH => 0x30; # Netbabel header length
use constant MAX_SERVERS   => 16;   # Maximum amount of servers in a packet

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
	foreach my $func (qw(receiver_hid receiver_uid server_count data_len servers)) {
		*{$func} = sub {
			my ($self,$arg) = @_;
		    return $self->{$private}->{$func} unless defined $arg;
			return $self->{$private}->{$func} = $arg;
		}
	}
}

# The following must be all on one line
my $VERSION = do { my @r = (q$Revision: 1.6 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

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
	my ($i, $off);
	
	$self->packet($data) if defined $data;

	#warn "Parsing";
	$self->SUPER::decode($data);

    # Zero the failure count, it will be incremented by dec if something
	# doesn't work.
	$priv->{error_count}  = 0;
	$priv->{receiver_uid} = $self->dec('receiver_uid', 0x0c, 4, 'L');
	$priv->{receiver_hid} = $self->dec('receiver_hid', 0x10, 2, 'S');
	$priv->{data_len}     = $self->dec('data_len'    , 0x2c, 4, 'L');
	$priv->{server_count} = $self->dec('server_count', 0x38, 4, 'L');
	$priv->{servers} = {};
	
	$off = 0x3c;
	
	if ($priv->{server_count} > MAX_SERVERS) {
		if($priv->{use_warnings}) {
			warn "Server count too high, 16 max: $priv->{server_count}";
		}

		return undef;
	}

	for($i=1;$i<=$priv->{server_count};$i++) {
		my $port =          $self->dec('port'        , $off  , 4, 'L');
		my $sid  =          $self->dec('server_id'   , $off+4, 4, 'L');
		my ($server, $ip);	
		$off += 8;

		($ip    , $off) = $self->_get_string($off);
		($server, $off) = $self->_get_string($off);
		
		$priv->{servers}->{$sid}->{friendlyname} = $server;
		$priv->{servers}->{$sid}->{address}      = $ip;
		$priv->{servers}->{$sid}->{port}         = $port;
	}
	
	
	return 1 if $priv->{error_count} == 0;
}

sub encode {
	my $self = shift;
	my $priv = $self->{$private};
	my $off;
	my $servers;
	my ($filler, $l);
	
	if(not defined $self->packet()) {
		my $p = "";
		$self->packet(\$p);
	}

	$priv->{server_count} = scalar keys %{$priv->{servers}};
	$priv->{data_len}     = $self->_calc_datalen();
	$filler               = chr(0) x ($priv->{data_len} + HEADER_LENGTH);
	$l                    = length($filler);

	$self->enc('filler'      , $filler              , 0x00, $l, 'a*');
	$self->SUPER::encode();
	
	$self->enc('unknown1'    , 0x28497650           , 0x04, 4 , 'L');
	$self->enc('unknown2'    , 0x000000eb           , 0x08, 4 , 'L');
	$self->enc('receiver_uid', $priv->{receiver_uid}, 0x0c, 4 , 'L');
	$self->enc('receiver_hid', $priv->{receiver_hid}, 0x10, 2 , 'S');
	$self->enc('unknown3'    , 0x00000002           , 0x14, 4 , 'L');
	$self->enc('data_len'    , $priv->{data_len}    , 0x2c, 4 , 'L');
	$self->enc('unknown4'    , 0x00000001           , 0x30, 4 , 'L');
	$self->enc('unknown5'    , 0x00000001           , 0x34, 4 , 'L');
	$self->enc('server_count', $priv->{server_count}, 0x38, 4 , 'L');	

	$off = 0x3c;
	foreach my $ssid (keys %{$priv->{servers}}) {
		my $serv = $priv->{servers}->{$ssid};
		
		$self->enc('port'     , $serv->{port}        , $off, 4                            , 'L');
		$off+=4;
		$self->enc('server_id', $ssid                , $off, 4                            , 'L');
		$off+=4;
		$self->enc('address'  , $serv->{address}     , $off, length($serv->{address})     , 'a*');
		$off+=length($serv->{address})+1;
		$self->enc('name'     , $serv->{friendlyname}, $off, length($serv->{friendlyname}), 'a*');
		$off+=length($serv->{friendlyname})+1;
	}

}

sub _calc_datalen {
	my $self = shift;
	my $priv = $self->{$private};
	my $ret = 4 + 4 + 4; # Unknown, Unknown, server count

	
	foreach my $serv (keys %{$priv->{servers}}) {
		$ret += length($priv->{servers}->{$serv}->{friendlyname});
		$ret += length($priv->{servers}->{$serv}->{address});
		$ret += (4 + 4 + 2); # Server ID + Port + Two zeroes
	}

	return $ret;
}

sub _get_string {
	my ($self, $off) = @_;
	my ($ret, $c);
	$c = "";
	
	while ($c ne chr(0)) {
		$ret .= $c;
		$c = $self->dec('string', $off, 1, 'a');		
		$off++;
	}

	return ($ret, $off);
	
}

sub packet_length {
	my $self = shift;
	my $priv = $self->{$private};

	return $priv->{data_len} + HEADER_LENGTH;
}

sub min_header_length {
	return HEADER_LENGTH;
}


1;
##########################################################################
# Change Log
##########################################################################
# $Log: AuthReply.pm,v $
# Revision 1.6  2003/04/20 01:51:18  vadim
# Deleted the part of the change log that didn't correspond to this module
#
# Revision 1.5  2003/04/15 01:01:59  vadim
# Encoding of data fixed and functional now.
#
# Removed username and password functions that were accidentally copied from
# Auth.pm
#
# Revision 1.4  2003/04/14 15:28:37  vadim
# Added packet_length and min_header_length methods
#
# Revision 1.3  2003/04/14 15:04:02  vadim
# Fixed several bugs and typos
#
# Revision 1.2  2003/04/11 00:14:34  vadim
# Added very experimental encoding functionality
#
# Revision 1.1  2003/04/08 23:06:08  vadim
# Added AuthReply packet type, already works.


# Settings for vim
# vim: ts=4
