#!/bin/sh
#
# This file needs to be put before standard 10_http and 10_https entries
# that accepts all connections that pass this limit test
# Add this in incoming before 10-http and 10-https
# cd ../incoming; touch 09-www-limit
#
# It creates a chain that checks on overlimit calls to ports 80 and 443
#
#
# Defines the limit value
# the burst value is default at 5
# These values are conservative, most humans will be working
# at 60/minute. This is intended to stop bots and scripts
LIMIT="limit rate 90/minute burst 30 packets"
# Comment out to stop kernel logging
# There is a pattern that looks for this string and
# continues to stop frequent offenders
LOGGER='log prefix "HTTP Overlimit "'

# Define type of address used
IPTYPE='ipv4_addr'
if [ "${PROTO}" = 'ip6' ]; then
    IPTYPE='ipv6_addr'
fi
cat <<EOF
table $PROTO filter {
      set ${PROTO}_www_limit {
       	  type ${IPTYPE}
	  timeout 60s
	  flags dynamic
      }
      chain wwwlimit {
	    update @${PROTO}_www_limit { $PROTO saddr ${LIMIT}} $COUNTER return
	    $COUNTER $LOGGER jump dropcounter
      }
}
EOF
# now add line to incoming chain to get to the added chain
echo add rule $PROTO $TABLE $CHAIN tcp dport {80,443} jump wwwlimit
