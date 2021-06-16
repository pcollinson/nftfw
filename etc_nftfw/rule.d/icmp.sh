#!/bin/sh
#
# Allow icmp for ipv4
#
if [ "$PROTO" = 'ip4' ]; then
    if [ "$DIRECTION" = 'incoming' ]; then
	ADDRCMD='saddr'
    else
	ADDRCMD='daddr'
    fi
    if [ "$IPS" != "" ]; then
	IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
    fi
    ICMP=icmp
    echo add rule $PROTO $TABLE $CHAIN $ICMP $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
