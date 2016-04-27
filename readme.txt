netatmo - weewx driver for netatmo weather stations
Copyright 2015 Matthew Wall

This driver has two modes of operation.  It can use the Netatmo API to obtain
data from the netatmo servers, or it can parse the packets sent from a netatmo
station.  The latter works only with netatmo firmware 102 (circa early 2015).

By default this driver will obtain data from the netatmo servers.


Installation instructions:

1) run the installer:

wee_extension --install weewx-netatmo.tgz

2) modify weewx.conf:

[Netatmo]
    username = INSERT_USERNAME_HERE
    password = INSERT_PASSWORD_HERE

3) start weewx:

sudo /etc/init.d/weewx start
