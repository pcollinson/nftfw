#!/bin/sh
#
# Add a chain to meter http traffic
#
# to use this install http meter rule BEFORE
# the normal http and https rules.
#
# install this in incoming.d as 06-pre-http-meter
# install the calling code as 09-http-meter
#
# You may want to adjust the limit rate
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
# add # below if you dpn't want kernel logginh
LOGGER='log prefix "HTTP Overlimit "'

# For testing
#DROPSTATEMENT='return'
# when live use
DROPSTATEMENT='jump dropcounter'

cat <<EOF
table $PROTO filter {
      chain httpaccept {
            meter http-meter { $PROTO saddr limit rate 30/minute} counter return
	    counter $LOGGER $DROPSTATEMENT
      }
}
EOF
