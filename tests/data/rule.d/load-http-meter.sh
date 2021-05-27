#!/bin/sh
#
# Add a chain to meter http traffic
#
# to use this install http meter rule in place
# of direct calls to http and https
#
# You may want to adjust the limit rate
# NB this is in the incoming table
# 
# It seems safer to drop packets
# when the meter causes a fail
#
# To list the meter
#
# nft list meter ip filter http-meter
# or
# nft list meter ip6 filter http-meter
#
LOGGER='log prefix "HTTP Overlimit "'
cat <<EOF
table $PROTO filter {
      chain httpaccept {
            meter http-meter { $PROTO saddr limit rate 20/minute} counter accept
	    counter $LOGGER jump dropcounter
      }
}
EOF


