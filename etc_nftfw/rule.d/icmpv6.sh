#!/bin/sh
#
# Allow icmp for ipv6
#
if [ "$PROTO" = 'ip6' ]; then
    if [ "$DIRECTION" = 'incoming' ]; then
	ADDRCMD='saddr'
    else
	ADDRCMD='daddr'
    fi
    if [ "$IPS" != "" ]; then
	IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
    fi
    ICMP=icmpv6
    echo add rule $PROTO $TABLE $CHAIN $ICMP $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
