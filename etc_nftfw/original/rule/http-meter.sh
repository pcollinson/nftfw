#!/bin/sh
# 
# Add metering to http/https rules
#
# Add 06-load-http-meter to incoming
# to pull in the chain
#
# NB defines rules for ports 80 and 443
# so replaces two entries in incoming.d
#
# Accept
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi    
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi    
echo add rule $PROTO $TABLE $CHAIN tcp dport '{80,443}' $IPSWITHDIRECTION $COUNTER $LOGGER jump httpaccept

