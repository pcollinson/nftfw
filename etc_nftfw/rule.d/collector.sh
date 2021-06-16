#!/bin/sh
#
# collector
# for compatibility with Symbiosis/Sympl
# add access to port 1919
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi
echo add rule $PROTO $TABLE $CHAIN tcp dport 1919 $IPSWITHDIRECTION $COUNTER $LOGGER accept
