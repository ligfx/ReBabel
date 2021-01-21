#!/usr/bin/perl -w
##########################################################################
# Creatures::DS::Netbabel::Packet
##########################################################################
# Author:      $Author: vadim $
# Date:        $Date: 2003/05/03 12:02:15 $
# Revision:    $Revision: 1.3 $
# Description: Base packet class. It contains the basic functionality
#              needed to determine the type of a packet, and provides
#              the base methods and features.
#

package     Creatures::DS::Netbabel::Packet::Login2;
use base qw(Creatures::DS::Netbabel::Packet);
use constant HEADER_LENGTH => 0x20; # Netbabel header length

=head1 NAME

Creatures::DS::Netbabel::Login1 - Purpose unknown

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
	foreach my $func (qw(unknown1)) {
		*{$func} = sub {
			my ($self,$arg) = @_;
		    return $self->{$private}->{$func} unless defined $arg;
			return $self->{$private}->{$func} = $arg;
		}
	}
}

# The following must be all on one line
my $VERSION = do { my @r = (q$Revision: 1.3 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

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
	my ($proto, $mod_dir) = @_;
	my $class = ref($proto) || $proto;
	my $self  = $class->SUPER::new();
	$self->{$private} = {};
	my $priv  = $self->{$private};
	
	    		
	bless($self, $class);	
	return $self;
}



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

	$self->packet($data) if defined $data;

	#warn "Parsing";
	$self->SUPER::decode($data);

	# Zero the failure count, it will be incremented by dec if something
	# doesn't work.
	$priv->{error_count}  = 0;
	$priv->{unknown1} = $self->dec('unknown1', 0x14, 4, 'L');
#	warn "Decoded value as ".$priv->{unknown1};

	return 1 if $priv->{error_count} == 0;
}

=head2 packet_length()

Returns the length of the raw packet data in bytes. As with get_data() this
could be inaccurate if encode() wasn't called after making changes.

=cut

sub packet_length {
	my $self = shift;
	my $priv = $self->{$private};

	return HEADER_LENGTH;
}

sub min_header_length {
	return HEADER_LENGTH;
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

	$filler               = chr(0) x (HEADER_LENGTH);
	$self->enc('filler'      , $filler              , 0x00, $l, 'a*');
	$self->SUPER::encode();

	$self->enc('unknown1'    , $priv->{unknown1}    , 0x14, 4 , 'L');

}


1;
##########################################################################
# Change Log
##########################################################################
# $Log: Login2.pm,v $
# Revision 1.3  2003/05/03 12:02:15  vadim
# Removed debug output
#
# Revision 1.2  2003/04/25 23:44:05  vadim
# Added PRAY parser class and test program. Both already seem to work with DS
# creatures and agents.
#
# Revision 1.1  2003/04/20 01:52:48  vadim
# Added parsers for the two unknown login1 and login2 packets. Whatever they do is unknown, but this is currently sufficent to get DS to login. Length is assumed to be always 32 bytes.
#


# Settings for vim
# vim: ts=4
