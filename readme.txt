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
automatically obtains and updates the tokens needed to get data from the
server.

<SG> 
I had to make some changes to Matt's code to get it to work correctly 
for me installation wise.

I had to tweak the packet sent to weewx to convert the mm to cm.

I also updated the way the rain was counted to match what some other drivers 
were doing (new daily total - old daily total give you rain from last check).  

Lastly, I updated this to actually use the rain rate provided by the netatmo
and also saved the battery status of the outdoor unit and the rain gauge.
</SG>

<SG>
Removed the rain rate, wasn't showing on PWSWeather correctly
</SG>

Installation instructions:

0) download the driver:

wget -O weewx-netatmo.zip https://github.com/scottgrey/weewx-netatmo/archive/master.zip

1) install the driver:

sudo wee_extension --install weewx-netatmo.zip

2) select and configure the driver:

sudo wee_config --reconfigure

3) start weewx:

sudo /etc/init.d/weewx start
