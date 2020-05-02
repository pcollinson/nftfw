#!/bin/sh
# 
# Allow tcp reset to pass
#
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi    
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi    
if [ "$PORTS" != "" ]; then
   echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION tcp flags '&' '(fin|syn|rst|ack) == rst' $COUNTER $LOGGER accept
else 
    echo add rule $PROTO $TABLE $CHAIN tcp flags '&' '(fin|syn|rst|ack) == rst' $COUNTER $LOGGER accept
fi    
