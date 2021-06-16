#!/bin/sh
#
# Putting this action into the firewall, causes problems when
# it's required to block a neighbour. The IPv6 control messages
# are blocked and selective blocking is not possible.
# The rules have been moved into nftfw_init.nft
exit
# Allow Essential icmps for IPV6
if [ "$PROTO" = 'ip6' ]; then
    if [ "$DIRECTION" = 'incoming' ]; then
	ADDRCMD='saddr'
    else
	ADDRCMD='daddr'
    fi
    if [ "$IPS" != "" ]; then
	IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
    fi
    echo add rule $PROTO $TABLE $CHAIN icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, parameter-problem} $IPSWITHDIRECTION $COUNTER $LOGGER accept
    echo add rule $PROTO $TABLE $CHAIN icmpv6 type {nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect} ip6 hoplimit 255 $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
