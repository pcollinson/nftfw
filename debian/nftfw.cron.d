#
#	Crontab entry for nftfw
#	Install in /etc/cron.d/nftfw
#
#
# Run blacklist test every 15 minutes
# allowing time for logs to accrue
#5,20,35,50 * * * * root /usr/bin/nftfw -q blacklist

# Run whitelist to check on logins
#10,25,40,55 * * * * root /usr/bin/nftfw -q whitelist

# check on firewall changes
# incron does some of this, but can miss events
# if many happen at once
#@hourly root /usr/bin/nftfw -q load

# Keep firewall database under control
#02 10 * * * root /usr/bin/nftfw -q tidy
