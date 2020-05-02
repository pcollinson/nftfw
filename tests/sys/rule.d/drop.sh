#!/bin/sh
# 
# Drop action
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi    
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi    
if [ "$PORTS" != "" ]; then
   echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER jump dropcounter
   echo add rule $PROTO $TABLE $CHAIN udp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER jump dropcounter
else
   echo add rule $PROTO $TABLE $CHAIN $IPSWITHDIRECTION $COUNTER $LOGGER jump dropcounter
fi   
