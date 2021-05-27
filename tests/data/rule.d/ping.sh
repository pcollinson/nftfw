#!/bin/sh
# 
# Allow inbound pings
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi    
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi    
if [ "$PROTO" = 'ip' ]; then
    ICMP=icmp
else
    ICMP=icmpv6
fi
# allow echo request
echo add rule $PROTO $TABLE $CHAIN $ICMP type '{echo-request}' $IPSWITHDIRECTION $COUNTER $LOGGER accept
# this the above rule might do will with a limit
#echo add rule $PROTO $TABLE $CHAIN $ICMP type '{echo-request}' limit rate 15/second $IPSWITHDIRECTION $COUNTER $LOGGER accept    
echo add rule $PROTO $TABLE $CHAIN $ICMP type '{echo-reply}' $IPSWITHDIRECTION $COUNTER $LOGGER accept

