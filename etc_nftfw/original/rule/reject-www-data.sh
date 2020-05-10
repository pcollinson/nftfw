#!/bin/sh
#
# Designed for outbound use, prevent packets from
# the webserver which is user "www-data" from sending anything other than domain requests.
# Unless the action file contains nominated IP addresses in its list
# Retained for compatibility - but no recommended for use
#
if [ "$DIRECTION" = 'incoming' ]; then
    exit 0
fi
cat <<EOF
table $PROTO filter {
      chain reject-www-data {
      	    tcp dport 53 $COUNTER $LOGGER accept
      	    udp dport 53 $COUNTER $LOGGER accept
      }
}
EOF
# white list any IPs
if [ "$IPS" != "" ]; then
    echo add rule $PROTO filter reject-www-data $PROTO daddr $IPS $COUNTER $LOGGER accept
fi
# add reject rule to end of the reject-www-data chain
echo add rule $PROTO filter reject-www-data $COUNTER $LOGGER jump rejectcounter
# add rule to outgoing to get to the chain
echo add rule $PROTO $TABLE $CHAIN meta skuid "www-data" $COUNTER $LOGGER jump reject-www-data
