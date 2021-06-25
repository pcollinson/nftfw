#!/bin/sh
#
# Allow icmp for ipv4
#
if [ "$PROTO" = 'ip' ]; then
    if [ "$DIRECTION" = 'incoming' ]; then
	ADDRCMD='saddr'
    else
	ADDRCMD='daddr'
    fi
    if [ "$IPS" != "" ]; then
	IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
    fi
    ICMP=icmp
    TYPES='{echo-reply,destination-unreachable,source-quench,redirect,echo-request,router-advertisement,router-solicitation,time-exceeded,parameter-problem,timestamp-request,timestamp-reply,info-request,info-reply,address-mask-request,address-mask-reply}'
    echo add rule $PROTO $TABLE $CHAIN $ICMP type $TYPES $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
