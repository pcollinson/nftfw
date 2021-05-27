#!/bin/sh
# 
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
