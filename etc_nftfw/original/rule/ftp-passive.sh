#!/bin/sh
#
# Add passive ports for pure-ftpd
# Get ports to be offered from pure's config file in
# /etc/pure-ftpd/conf/PassivePortRange
# NB this rule does nothing unless PORTS are established
if [ "$DIRECTION" = 'incoming' ]; then
    ADDRCMD='saddr'
else
    ADDRCMD='daddr'
fi
if [ "$IPS" != "" ]; then
    IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
fi

if [ -f /etc/pure-ftpd/conf/PassivePortRange ]; then
   PORTS=$(awk '{printf "{%s-%s}\n", $1,$2}' /etc/pure-ftpd/conf/PassivePortRange)
fi
# If you are not using pure, comment line above and replace with the desired
# numeric port range
#PORTS={FROMPORT-TOPORT}
if [ "$PORTS" != "" ]; then
    echo add rule $PROTO $TABLE $CHAIN tcp dport $PORTS $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
