#!/bin/sh
# 
# syn-ack-flood-protection
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
echo add rule $PROTO $TABLE $CHAIN $IPSWITHDIRECTION ct state invalid $COUNTER $LOGGER jump dropcounter
