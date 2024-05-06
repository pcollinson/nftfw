% Installing Maxmind Geolocation
# Installing Maxmind Geolocation

This page was originally written for Debian buster, in the lines below replace 'buster' by the name of your system.

## Install the python modules

``` sh
$ sudo apt install python3-geoip2
$ sudo apt install geoipupdate
```

#### ```geoipupdate``` is not found - Debian

If ```geoipupdate``` is not found, you need to change ```/etc/apt/sources.list``` to include contributed packages.

Edit ```/etc/apt/sources.list``` and look for:

``` sh
deb URL/debian buster main
```

and change to:
``` sh
deb URL/debian buster main contrib
```

Now try the ```apt install geoipupdate``` again, it should work now.

Debian should have installed at least the 3.1.1 version of ```geoipupdate```.  You'll see the version when it installed, this becomes important later. To check it:

``` sh
$ apt show geoipupdate
```

#### ```geoipupdate``` is not found - Raspberry Pi OS

It seems that this package is not available on RPi servers. However, compiled versions for the 32-bit armhf architecture exists on the internet. Visit

``` text
https://packages.debian.org/buster/armhf/geoipupdate/download
```
Clicking on a link on that page should download a Debian package that can be installed; you should get a file called ```geoipupdate_3.1.1-1_armhf.deb```. Then

``` sh
$ sudo dpkg -i ./geoipupdate_3.1.1-1_armhf.deb
```
will install the package for you.

You have all the bits we need, we'll set them up later.

## Getting a MaxMind Account

Visit the [Maxmind web site](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Read down the page and click on 'SIGN UP FOR GEOLITE2'. Create your account, I selected 'Internet Security' for 'Intended Use'.

Once you have the account, go to [Maxmind's Account portal](https://www.maxmind.com/en/account/login) and login. You can also get there from the head and shoulders icon in the menu bar on their site.

Once logged in, you land on a page that appears to have nothing apart from frightening messages. However, scroll down, looking In the menu on the left-hand side and click on 'My License Key' under Services.

Once there,  copy and store your Account/User ID, you'll need it later.

Click on 'Generate new license key'.

Enter a name for the key, I'm using a machine name.

 TIck the radio button to select use with geoipupdate version 3.1.1.

Click on 'Confirm'.

This is the only time you will see the full version of the key, so copy and paste it somewhere safe. There's an icon next to the key that will copy it to your clipboard. If the next step fails, you can edit the ```geoipupdate``` config file from the information you have.

Now click on 'Download Config' - this will create a local file called _GeoIP.conf_.

## Installing the key

The Debian installation will have created ```/etc/GeoIP.conf``` for you. The file pre-dates the Maxmind decision to ask you to sign up for a free license, ignore the comment above the _AccountID_ line. You need to set the:

- AccountID _to your account id_
- LicenseKey _to your License Key_
- EditionIDs _to_ ```GeoLite2-ASN GeoLite2-City GeoLite2-Country```

you can do this by copying the downloaded file into place, or by editing the file. You'll need to _sudo_ your edit or _cp_.

Now run:

``` sh
$ sudo geoipupdate -v

```

and it should download a new set of files. These will be put in ```/var/lib/GeoIP``` and an ```ls``` will show them.

## Finally check on cron

The Debian installer will have installed a cron file

``` sh
/etc/cron.d/geoipupdate
```

that updates the files automatically  once a week. I suggest that you change the time of day somewhat so that you are not clashing with other Debian systems in your timezone.
