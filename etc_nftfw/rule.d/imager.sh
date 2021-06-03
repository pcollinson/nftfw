#!/bin/sh
#
# imager
# for compatibility with Symbiosis/Sympl
# add access to port 5000
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi
echo add rule $PROTO $TABLE $CHAIN tcp dport 5000 $IPSWITHDIRECTION $COUNTER $LOGGER accept
