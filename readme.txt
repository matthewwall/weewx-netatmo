netatmo - weewx driver for netatmo weather stations
Copyright 2015 Matthew Wall

This driver has two modes of operation.  It can use the netatmo API to obtain
data from the netatmo servers, or it can parse the packets sent from a netatmo
station.  The latter works only with netatmo firmware 101 (circa early 2015).
Firmware 102 introduced arbitrary encryption in response to a poorly chosen
decision to include the wifi password in network traffic sent to the netatmo
servers.  Unfortunately, the encryption blocks end-users from accessing their
data, while the netatmo stations might still send information such as the wifi
password to the netatmo servers.

By default this driver will operate in 'cloud' mode.

Communication with the netatmo servers requires 4 things: username, password,
client_id, and client_secret.  The username and password are the credentials
used to access data at netatmo.com.  The client_id and client_secret must be
obtained via the dev.netatmo.com web site.  Using these 4 things, the driver
automatically obtains and updates the tokens needed to get data from the server.


Installation instructions:

1) run the installer:

wee_extension --install weewx-netatmo.tgz

2) modify weewx.conf:

[Netatmo]
    username = INSERT_USERNAME_HERE
    password = INSERT_PASSWORD_HERE
    client_id = INSERT_CLIENT_ID_HERE
    client_secret = INSERT_CLIENT_SECRET_HERE

3) start weewx:

sudo /etc/init.d/weewx start
