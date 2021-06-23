#!/bin/sh
#
# Allow icmp for ipv6
#
if [ "$PROTO" = 'ip6' ]; then
    if [ "$DIRECTION" = 'incoming' ]; then
	ADDRCMD='saddr'
    else
	ADDRCMD='daddr'
    fi
    if [ "$IPS" != "" ]; then
	IPSWITHDIRECTION="$PROTO $ADDRCMD $IPS"
    fi
    ICMP=icmpv6
    # These types dealt with by default in nftfw_init.nft
    # destination-unreachable, packet-too-big, time-exceeded, parameter-problem
    # nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect
    # so omitted here
    TYPES='{echo-request,echo-reply,mld-listener-query,mld-listener-report,mld-listener-done,mld-listener-reduction,router-renumbering,ind-neighbor-solicit,ind-neighbor-advert,mld2-listener-report}'
    echo add rule $PROTO $TABLE $CHAIN $ICMP type $TYPES $IPSWITHDIRECTION $COUNTER $LOGGER accept
fi
