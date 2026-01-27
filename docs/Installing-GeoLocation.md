% Installing Maxmind Geolocation
# Installing Maxmind Geolocation

_nftfw_ can optionally use geolocation in _nftfwls_ and _nftfwadm_ to display the two-letter country code that is believed to be the location of that address. The code in these programs looks for the installation of the appropriate libraries and will work without them.  In addition, it can be used to generate files for _blacknets.d_, where lists of IP addresses and address ranges can be used to block access to your system from named countries - see [Getting CIDR lists](Getting-cidr-lists.md).

Debian comes with an older version of the MaxMind data, using a now unused MaxMind data format. The files for this system are stored in _/usr/share/GeoIP_. _nftfw_ doesn't use this legacy system and opted for the current data formats provided on a weekly basis by Maxmind.

Maxmind wants you to have free access to their files, you just need to sign up. The data files will be stored in _/var/lib/GeoIP/_.

## Install the python modules

``` sh
$ sudo apt install python3-geoip2
$ sudo apt install geoipupdate
```

#### _geoipupdate_ is not found - Debian

If _geoipupdate_ is not found, you need to change _/etc/apt/sources.list_ to include contributed packages.

Edit _/etc/apt/sources.list_ and look for

``` sh
deb URL/debian YOURVERSION main
```

and change to:
``` sh
deb URL/debian YOURVERSION main contrib
```

Now try the _apt install geoipupdate_ again, it should work now.

You have all the bits we need, we'll set them up later.

## Getting a MaxMind Account

Visit the [Maxmind web site](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Read down the page and click on 'Sign Up For Geolite2'. Create your account, I selected 'Internet Security' for 'Intended Use'.

Once you have the account, go to [Maxmind's Account portal](https://www.maxmind.com/en/account/sign-in) and login. You can also get there from the head and shoulders icon in the menu bar on their site.

The site is considerably more friendly than it used to be. Take a note of your Account/User ID, that appears at the top of the menu, you'll need it later.

Click on 'Manage license keys' and follow the prompts..

Enter a name for the key, I'm using a machine name.

This is the only time you will see the full version of the key, so copy and paste it somewhere safe. There's an icon next to the key that will copy it to your clipboard. If the next step fails, you can edit the _geoipupdate_ config file from the information you have.

Now click on 'Download Config' - this will create a local file called _GeoIP.conf_.

## Installing the key

The Debian installation will have created _/etc/GeoIP.conf_ for you. The file pre-dates the Maxmind decision to ask you to sign up for a free license, ignore the comment above the _AccountID_ line. You need to set the:

- AccountID _to your account id_
- LicenseKey _to your License Key_
- EditionIDs _to_ _GeoLite2-ASN GeoLite2-City GeoLite2-Country_

you can do this by copying the downloaded file into place, or by editing the file. You'll need to _sudo_ your edit or _cp_.  The _nftfw_ commands use GeoLite2-Country.

Now run:

``` sh
$ sudo geoipupdate -v

```

and it should download a new set of files ending in  _.mmdb_. These will be put in _/var/lib/GeoIP_ and an _ls_ will show them.

## Finally check on cron

The Debian installer will have installed a cron file

``` sh
/etc/cron.d/geoipupdate
```

that updates the files automatically  once a week. I suggest that you change the time of day somewhat so that you are not clashing with other Debian systems in your timezone.
