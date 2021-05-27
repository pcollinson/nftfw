#!/bin/sh
# 
# related connections
#
# This rule has been added into nftfw_init.nft
# because it needs to happen before firewall testing
# so that testing only happens on initial connections
#
# included for symbiosis compatibility
exit
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi    
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi    
if [ "$PORTS" != "" ]; then
   echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION ct state related $COUNTER $LOGGER accept
   echo add rule $PROTO $TABLE $CHAIN udp dport $PORTS $IPSWITHDIRECTION ct state related $COUNTER $LOGGER accept
else 
    echo add rule $PROTO $TABLE $CHAIN ct state related $COUNTER $LOGGER accept
fi    
