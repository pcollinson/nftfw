#!/bin/sh
# 
# From the nft manual page
#
# Provide ftp helper
if [ "$DIRECTION" = 'outgoing' ]; then
    exit
fi
# add helper
cat <<EOF
table $PROTO filter {
      ct helper ftp-standard {
      	 type "ftp" protocol tcp
      }
}
EOF
# add line to prerouting chain
echo add rule $PROTO $TABLE prerouting tcp dport 21 ct helper 'set "ftp-standard"'
