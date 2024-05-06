#!/bin/sh
#
# Accept and log action
# The idea of this rule is to temporarily replace a 99-drop rule
# in outgoing.d or incoming.d with a rule that logs packets that
# would be dropped by default.
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi
# add special logger so only this rule is logged
LOGGER='log prefix "DRYRUN DROP "'
if [ "$PORTS" != "" ]; then
   echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER accept
   echo add rule $PROTO $TABLE $CHAIN udp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER accept
else
   echo add rule $PROTO $TABLE $CHAIN $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
