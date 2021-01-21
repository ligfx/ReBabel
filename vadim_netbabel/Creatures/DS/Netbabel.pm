#!/usr/bin/perl -w
##########################################################################
# Creatures::DS::Netbabel::Packet
##########################################################################
# Author:      $Author: vadim $
# Date:        $Date: 2003/05/10 19:31:29 $
# Revision:    $Revision: 1.9 $
# Description: Base packet class. It contains the basic functionality
#              needed to determine the type of a packet, and provides
#              the base methods and features.
#

package Creatures::DS::Netbabel;

=head1 NAME

Creatures::DS::Netbabel - Netbabel decoder

=head1 SYNOPSIS

  #!/usr/bin/perl -w
  use Creatures::DS::Netbabel;
  my $nbd    = new Creatures::DS::Netbabel;
  my $packet = $dbd->decode($data);
  print $packet->length();

=head1 GET/SET METHODS

This module contains several functions that work in the same way: calling the
function with an argument changes a setting, and calling it with no argument
returns the current setting.

When calling the function with an argument the return value is currently
the passed argument. This may change in the future.

=head2 use_warnings(I<$warn>)

Gets/sets the use_warnings setting. When it is set the module will generate
warnings if something doesn't look right. In any case, error codes will be
returned.

=cut

use Carp;
use strict;
use Creatures::DS::Netbabel::Packet;
use Creatures::DS::Netbabel::Packet::Message;
use Creatures::DS::Netbabel::Packet::Auth;
use Creatures::DS::Netbabel::Packet::AuthReply;
use Creatures::DS::Netbabel::Packet::Login1;
use Creatures::DS::Netbabel::Packet::Login2;
use Creatures::C3::KeyValue;
use Creatures::C3::PRAY;

BEGIN {
	# This really odd thing is brought to you by Dylan! Actually, it's pretty
	# cool. This code automatically creates the functions to get/set fields,
	# which is nice since they all have the same code.

	my $private = __PACKAGE__;

	no strict 'refs';
	foreach my $func (qw(pk_rawtype)) {
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


=head1 METHODS

=head2 new(I<$packet>)

Creates a new object, decoding the packet in I<$packet> if specified. This is
equivalent to calling new() with no arguments and then calling
$obj->decode(I<$packet>).

=cut

sub new {
	my ($proto, $data) = @_;
	my $class = ref($proto) || $proto;
	my $self  = {};
	$self->{$private} = {};
	my $priv  = $self->{$private};

	# Create an instance of this class to determine the packet
	# type. We keep it in memory to improve speed.
	$priv->{nb_packet} = new Creatures::DS::Netbabel::Packet;

	bless($self, $class);

	$self->decode($data) if defined $data;

	return $self;
}

=head2 (I<$pkt>, I<$length>, I<$hlen>) = decode(I<$data>)

Decodes a packet contained in $data. If the use_warnings setting is set then
any invalid values detected in the packet will produce a warning. Attempts to
encode a packet that was not decoded correctly will also fail, and the
original values will be preserved in the failed places.

This function will return an instance of the appropiate class for the packet
in I<$pkt>, the full length of the packet in I<$length>, and the minimum header
length in I<$hlen>. If the type of the packet can't be determined undef will
be returned.

This function works with partial packets. If you pass it a packet that's too
small to parse it will return undef in I<$pkt>, and the amount of bytes needed
to parse the header in I<$hlen>.

You should check the $pkt->type() method to determine what kind of packet you
got, and what you can do with it.

=cut


sub decode {
	my $self = shift;
	my $priv = $self->{$private};
	my $data = shift;
	my ($rawtype, $type);
	my ($ret, $length, $hlen);

	# XXX This isn't very efficent. First we run the generic decode
	# to find the packet type, and then we parse it with a class that
	# inherits the generic decode, so this operation will be done
	# twice.
	$priv->{nb_packet}->decode($data);
	$type    = $priv->{nb_packet}->type();
	$rawtype = $priv->{nb_packet}->raw_type();
	$priv->{pk_rawtype} = $rawtype; # Save type in case we can't figure it out

	if(not defined $type) {
		if( $priv->{use_warnings} ) {
			warn "Unknown packet type";
		}
		return undef;
	}

	$ret = $self->make($type);

	if (not defined($ret) ) {
		if ( $priv->{use_warnings}) {
			warn "Packet type '$type', code $rawtype is known but not implemented";
			# The user can check the packet's magic byte in pk_rawtype();
		}

		return undef;
	}

	# Pass our use_warnings setting to the instance of the class
	$ret->use_warnings($priv->{use_warnings});
	$hlen = $ret->min_header_length();

	if( length($$data) >= $hlen ) {
		# We've got enough data to do the decoding, so we do it.
		$ret->decode($data);
		$length = $ret->packet_length();
	} else {
		# Not enough data yet, the user will have to get at least
		# $hlen bytes and then try again.
		$ret = undef;
		$length = undef;
	}
	
	return ($ret, $length, $hlen);
}

sub make {
	my ($self, $type) = @_;
	my $priv = $self->{$private};
	my $ret;
	
	for($type) {
		if      (/^message$/) {
			$ret = new Creatures::DS::Netbabel::Packet::Message;
		} elsif (/^auth$/) {
			$ret = new Creatures::DS::Netbabel::Packet::Auth;
		} elsif (/^auth_reply$/) {
			$ret = new Creatures::DS::Netbabel::Packet::AuthReply;
		} elsif (/^login1$/) {
			$ret = new Creatures::DS::Netbabel::Packet::Login1;
		} elsif (/^login2$/) {
			$ret = new Creatures::DS::Netbabel::Packet::Login2;
		}
	}
	
	if(defined $ret) {
		$ret->type($type);
	}
	
	return $ret;
}

sub make_message {
	my $self = shift;
	my $priv = $self->{$private};
	my ($sender_uid, $sender_hid, $receiver_uid, $receiver_hid, $message) = @_;

	my $pk   = $self->make('message');
	my $pray = new Creatures::C3::PRAY;
	my $kv;
	my %data;
	
	$pk->sender_uid($sender_uid);
	$pk->sender_hid($sender_hid);

	if(defined $receiver_uid) {
		$pk->has_receiver(1);
		$pk->receiver_uid($receiver_uid);
		$pk->receiver_hid($receiver_hid);
	} else {
		$pk->has_receiver(0);
	}

	$data{'Chat Message'}      = "<tint 96 160 128 128 128>$message";
	$data{'ChatID'}            = "kiwi (20030428165405) - 1+1";
	$data{'Chat Message Type'} = "Message";
	$data{'Sender Nickname'}   = "Valhalla";
	$data{'Sender UserID'}     = "1+1";
	
	$kv = "\0" . hash_to_kv(%data) . "\0";
	$pray->add_compressed_file(undef, '27+120030428165405_chatmessage', 'CHAT', \$kv);
	my $enc = $pray->encode();
	$pk->PRAY($enc);
	return $pk;

#	$pk->encode();
#	return $pk->packet();
}

sub use_warnings {
	my ($self, $setting) = @_;
	my $priv = $self->{$private};
	
	warn "use_warnings set to $setting";
	return $priv->{use_warnings} if not defined $setting;
	$priv->{use_warnings} = $setting;
	$priv->{nb_packet}->use_warnings($setting);
	return $setting;
	
}

1;
##########################################################################
# Change Log
##########################################################################
# $Log: Netbabel.pm,v $
# Revision 1.9  2003/05/10 19:31:29  vadim
# Some debugging added for unknown packets
#
# Revision 1.8  2003/04/29 00:30:42  vadim
# Message encoding mostly done, at least it can re-encode a decoded one.
# PRAY encoding finished (seems to work at least)
# KeyValue kind of working (seems to have trouble with numerical values)
# Packet.pm tweaked a bit to allow omiting the length
# Netbabel now has a make_message function.
# parsedump improved to dump more information and check message encoding.
#
# Revision 1.7  2003/04/20 01:54:30  vadim
# Added support for login1 and login2
#
# Revision 1.6  2003/04/15 01:02:55  vadim
# Fixed creation of new packets, the type wasn't being set.
#
# Revision 1.5  2003/04/14 17:41:25  vadim
# Changed decode to work on a scalar reference instead. This allows to decode
# the header once, fetch the rest of the data and read the data from the
# packet directly without a second decode call.
#
# Revision 1.4  2003/04/08 23:06:26  vadim
# Added AuthReply support.
#
# Revision 1.3  2003/04/08 16:28:49  vadim
# Moved packet object creations to make()
#
# Revision 1.2  2003/04/06 21:39:01  vadim
# Commented function generator in Netbabel class.
# Enabled processing of Message packets in Netbabel
# Added use_warnings setting.
#
# Revision 1.1  2003/04/06 01:31:29  vadim
# Added Netbabel.pm module, which works as a frontend to packet classes.
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
