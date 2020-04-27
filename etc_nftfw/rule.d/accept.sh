#!/bin/sh
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
if [ "$PORTS" != "" ]; then
   echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER accept
   echo add rule $PROTO $TABLE $CHAIN udp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER accept
else
   echo add rule $PROTO $TABLE $CHAIN $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi   
