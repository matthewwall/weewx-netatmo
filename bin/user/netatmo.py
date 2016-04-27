#!/usr/bin/python
# Copyright 2015 Matthew Wall
#
# Thanks to phillippe larduinat for publishing lnetatmo.py
#   https://github.com/philippelt/netatmo-api-python
#
# Shame on netatmo for making it very difficult to get data from the hardware
# without going through their servers.

from __future__ import with_statement
import Queue
import json
import re
import socket
import syslog
import threading
import time
from urllib import urlencode
import urllib2

import weewx.drivers
import weewx.engine
import weewx.units

DRIVER_NAME = 'Netatmo'
DRIVER_VERSION = "0.2"

def logmsg(level, msg):
    syslog.syslog(level, 'netatmo: %s: %s' %
                  (threading.currentThread().getName(), msg))

def logdbg(msg):
    logmsg(syslog.LOG_DEBUG, msg)

def loginf(msg):
    logmsg(syslog.LOG_INFO, msg)

def logerr(msg):
    logmsg(syslog.LOG_ERR, msg)

def loader(config_dict, engine):
    return NetatmoDriver(**config_dict[DRIVER_NAME])


class NetatmoDriver(weewx.drivers.AbstractDevice):
    # map from netatmo names to database schema names
    DEFAULT_SENSOR_MAP = {
        'pressure': 'pressure',
        'temperature_in': 'inTemp',
        'humidity_in': 'inHumidity',
        'temperature_out': 'outTemp',
        'humidity_out': 'outHumidity',
        'temperature_1': 'extraTemp1',
        'humidity_1': 'extraHumid1',
        'temperature_2': 'extraTemp2',
        'humidity_2': 'extraHumid2',
        'temperature_3': 'extraTemp3',
        'humidity_3': 'extraHumid3',
        'wind_speed': 'windSpeed',
        'wind_dir': 'windDir',
        'rain': 'rain',
        'co2': 'co2',
        'noise': 'noise'}

    def __init__(self, **stn_dict):
        loginf("driver version is %s" % DRIVER_VERSION)
        self.sensor_map = stn_dict.get('sensor_map', NetatmoDriver.DEFAULT_SENSOR_MAP)
        mode = stn_dict.get('mode', 'cloud')
        self.max_tries = int(stn_dict.get('max_tries', 5))
        self.retry_wait = int(stn_dict.get('retry_wait', 10)) # seconds
        self.poll_interval = int(stn_dict.get('poll_interval', 600)) # seconds
        timeout = int(stn_dict.get('timeout', 3))
        port = int(stn_dict.get('port', 4200))
        addr = stn_dict.get('host', '')
        if mode == 'sniff':
            self.collector = PacketSniffer(addr, port)
        else:
            self.collector = CloudClient()
        self.collector.startup()
    
    def closePort(self):
        self.collector.shutdown()

    @property
    def hardware_name(self):
        return DRIVER_NAME

    def genLoopPackets(self):
        while True:
            try:
                data = self.collector.queue.get(True, 10)
                pkt = self.data_to_packet(data)
                if pkt:
                    yield pkt
            except Queue.Empty:
                logdbg('empty queue')

    def data_to_packet(data):
        # convert netatmo data to format, units, and scaling for database
        packet = {'dateTime': int(time.time() + 0.5), 'usUnits': weewx.METRIC}
        for n in data:
            if n in self.sensor_map:
                packet[sensor_map[n]] = data[n]
        return packet


class Collector(object):
    queue = Queue.Queue()

    def startup(self):
        pass

    def shutdown(self):
        pass


class CloudClient(Collector):
    """Poll the netatmo servers for data.  Put the result on the queue.

    The netatmo server provides the following data:
    
    
    """

    NETATMO_URL = 'https://api.netatmo.net/'
    AUTH_URL = NETATMO_URL + 'oauth2/token'
    GETUSER_URL = NETATMO_URL + 'api/getuser'
    DEVICELIST_URL = NETATMO_URL + 'api/devicelist'
    GETMEASURE_URL = NETATMO_URL + 'api/getmeasure'

    def __init__(self, poll_interval):
        self._poll_interval = poll_interval

    def startup(self):
        auth = ClientAuth(client_id, client_secret, username, password)
        devices = DeviceList(auth)
        while True:
            latest = devices.last_data()
            logdbg('latest: %s' % latest)
            Collector.queue.put(latest)
            time.sleep(self._poll_interval)

    class ClientAuth(object):
        def __init__(self, client_id, client_secret, username, password):
            params = {
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
                'scope': 'read_station'}
            resp = CloudClient.post_request(self.AUTH_URL, params)
            self._client_id = client_id
            self._client_secret = client_secret
            self._access_token = resp['access_token']
            self._refresh_token = resp['refresh_token']
            self._scope = resp['scope']
            self._expiration = int(resp['expire_in'] + time.time())

        @property
        def access_token(self):
            if self._expiration < time.time():
                params = {
                    'grant_type': 'refresh_token',
                    'refresh_token': self._refresh_token,
                    'client_id': self._client_id,
                    'client_secret': self._client_secret}
                resp = CloudClient.post_request(self.AUTH_URL, params)
                self._access_token = resp['access_token']
                self._refresh_token = resp['refresh_token']
                self._expiration = int(resp['expire_in'] + time.time())

    class User(object):
        def __init__(self, auth_data):
            params = {
                'access_token': auth_data.access_token}
            resp = CloudClient.post_request(GETUSER_URL, params)
            self._raw_data = resp['body']
            self._id = self._raw_data['_id']
            self._devices = self._raw_data['devices']
            self._ownermail = self._raw_data['mail']

    class DeviceList(object):
        def __init__(self, auth_data):
            self._token = auth_data.access_token
            params = {
                'access_token': self._token,
                'app_type': 'app_station'}
            resp = CloudClient.post_request(DEVICELIST_URL, params)
            self._raw_data = resp['body']
            self._statiosn = {d['_id'] : d for d in self._raw_data['devices']}
            self._modules = {m['_id'] : m for m in self._raw_data['modules']}
            self._default = list(self._stations.values())[0]['station_name']

        def module_names(self, station=None):
            res = [m['module_name'] for m in self._modules.values()]
            res.append(self.station_by_name(station)['module_name'])
            return res

        def station_by_name(self, station=None):
            if not station:
                station = self._default_station
            for i, s in self._stations.items():
                if s['station_name'] == station:
                    return self._stations[i]
            return None

        def station_by_id(self, sid):
            return None if sid not in self._stations else self._stations[sid]

        def module_by_name(self, module, station=None):
            s = None
            if station:
                s = self.station_by_name(station)
                if not s:
                    return None
            for m in self._modules:
                mod = self._modules[m]
                if mod['module_name'] == module:
                    if not s or mod['main_device'] == s['_id']:
                        return mod
            return None

        def module_by_id(self, mid, sid=None):
            s = self.station_by_id(sid) if sid else None
            if mid in self._modules:
                if not s or self.modules[mid]['main_device'] == s['_id']:
                    return self.modules[mid]
            return None

        def get_measure(self, device_id, scale, mtype, module_id=None,
                        date_begin=None, date_end=None, limit=None,
                        optimize=False, real_time=False):
            params = {
                'access_token': self._token,
                'device_id': device_id,
                'scale': scale,
                'type', mtype,
                'optimize': 'true' if optimize else 'false',
                'real_time': 'true' if real_time else 'false'}
            if module_id:
                params['module_id'] = module_id
            if date_begin:
                params['date_begin'] = date_begin
            if date_end:
                params['date_end'] = date_end
            if limit:
                params['limit'] = limit
            return CloudClient.post_request(GETMEASURE_URL, params)

        def last_data(self, station=None, exclude=0):
            s = self.station_by_name(station)
            if not s:
                return None
            data = dict()
            limit = (time.time() - exclue) if exclude else 0
            ds = s['dashboard_data']
            if ds['time_utc'] > limit:
                data[s['module_name']] = ds.copy()
                data[s['module_name']]['When'] = data[s['module_name']].pop('time_utc')
                data[s['module_name']]['wifi_status'] = s['wifi_status']
            for mid in s['modules']:
                ds = self._modules[mid]['dashboard_data']
                if ds['time_utc'] > limit:
                    mod = self._modules[mid]
                    data[mod['module_name']] = ds.copy()
                    data[mod['module_name']]['When'] = data[mod['module_name']].pop('time_utc')
                    for i in ('battery_vp', 'rf_status'):
                        if i in mod:
                            data[mod['module_name']][i] = mod[i]
            return data

    @staticmethod
    def post_request(url, params):
        # netatmo response body size is limited to 64K
        params = urlencode(params)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded;charset=urf-8"}
        req = urllib2.Request(url=url, data=params, headers=headers)
        resp = urllib2.urlopen(req).read(65535)
        return json.loads(resp)


class PacketSniffer(Collector):
    """listen for incoming packets then parse them.  put result on queue."""

    def startup(self):
        pass

    def shutdown(self):
        pass


class TCPPacket(object):
    _HDR = re.compile('(\d+).(\d+) IP (\S+) > (\S+):')
    _DATA = re.compile('0x00\d0: (.*)')

    def lines2packets(lines):
        pkts = []
        ts = None
        src = None
        dst = None
        data = []
        for line in lines:
            line = line.strip()
            TCPPacket._HDR.search(line)
            if m:
                ts = m.group(1)
                src = m.group(3)
                dst = m.group(4)
                data = []
                pkts.append({'dateTime': ts, 'src': src, 'dst': dst,
                             'data': ''.join(data)})
                continue
            TCPPacket._DATA.search(line)
            if m:
                data.append(m.group(1))
                continue
        return pkts

    @staticmethod
    def parse_data(data):
        pkt = dict()
        return pkt


# To test this driver, do the following:
#   PYTHONPATH=bin python user/netatmo.py
if __name__ == "__main__":
    usage = """%prog [options] [--help]"""

    def main():
        import optparse
        syslog.openlog('wee_netatmo', syslog.LOG_PID | syslog.LOG_CONS)
        parser = optparse.OptionParser(usage=usage)
        parser.add_option('--test-sniff', dest='ts', action='store_true',
                          help='test the driver in packet sniff mode')
        parser.add_option('--test-cloud', dest='tc', action='store_true',
                          help='test the driver in cloud client mode')
        parser.add_option('--test-parse', dest='tp', action='store_true',
                          help='test the parser')
        parser.add_option('--username', dest='username', metavar='USERNAME',
                          help='username for cloud mode')
        parser.add_option('--password', dest='password', metavar='PASSWORD',
                          help='password for cloud mode')
        parser.add_option('--get-cloud_data', dest='data', action='store_true',
                          help='get all cloud data')
        (opts, args) = parser.parse_args()

        if opts.ts:
            test_packet_driver()
        if opts.tc:
            test_cloud_driver(opts.username, opts.password)
        if opts.tp:
            test_parse()

    def test_sniff_driver():
        import weeutil.weeutil
        driver = NetatmoDriver({'mode': 'sniff'})
        for pkt in driver.genLoopPackets():
            print weeutil.weeutil.timestamp_to_string(pkt['dateTime']), pkt

    def test_cloud_driver(username, password):
        import weeutil.weeutil
        driver = NetatmoDriver({'mode': 'cloud',
                                'username': username, 'password': password})
        for pkt in driver.genLoopPackets():
            print weeutil.weeutil.timestamp_to_string(pkt['dateTime']), pkt

    def get_cloud_data(username, password):
        auth = CloudClient.ClientAuth(username, password)
        devices = CloudClient.DeviceList(auth)
        for module, module_data in devices.last_data(exclue=3600).items():
            print module
            for sensor, value in module_data.items():
                if sensor == 'When':
                    value = time.strftime("%Y.%m.%d %H:%M:%S",
                                          time.localtime(value))
                print "%30s: %s" % (sensor, value)

    def test_parse():
        tcp_lines = """1450840574.054884 IP 10.1.10.11.56280 > b31.netatmo.net.25050: P 52:56(4) ack 33 win 2968
    0x0000:  4500 002c 7ba7 0000 fe06 f2f2 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 80ee d800 3574
    0x0020:  5018 0b98 1bbe 0000 7601 0000 0000
1450840574.153985 IP b31.netatmo.net.25050 > 10.1.10.11.56280: P 33:37(4) ack 56 win 29200
    0x0000:  4520 002c da5b 4000 3406 1e1f 3ed2 fb53
    0x0010:  0a01 0a0b 61da dbd8 d800 3574 f828 80f2
    0x0020:  5018 7210 cb42 0000 6000 0000 0000
1450840574.262671 IP 10.1.10.11.56280 > b31.netatmo.net.25050: P 56:202(146) ack 37 win 2964
    0x0000:  4500 00ba c99d 0000 fe06 a46e 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 80f2 d800 3578
    0x0020:  5018 0b94 3750 0000 6100 2500 c210 7a56
    0x0030:  3730 3a65 653a 3530 3a30 363a 3834 3a37
    0x0040:  3200 da00 0137 0fa5 2703 d227 0731 05b7
    0x0050:  0761
1450840574.363385 IP b31.netatmo.net.25050 > 10.1.10.11.56280: P 37:41(4) ack 202 win 30016
    0x0000:  4520 002c da5c 4000 3406 1e1e 3ed2 fb53
    0x0010:  0a01 0a0b 61da dbd8 d800 3578 f828 8184
    0x0020:  5018 7540 217d 0000 0600 0000 0000
1450840574.464212 IP 10.1.10.11.56280 > b31.netatmo.net.25050: P 202:443(241) ack 41 win 2960
    0x0000:  4500 0119 25c4 0000 fe06 47e9 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 8184 d800 357c
    0x0020:  5018 0b90 132d 0000 1000 0100 0507 00e8
    0x0030:  002b 0100 0000 0032 3032 3a30 303a 3030
    0x0040:  3a30 363a 3836 3a32 3836 a615 0000 2b00
    0x0050:  e811
1450840574.568157 IP b31.netatmo.net.25050 > 10.1.10.11.56280: P 41:45(4) ack 443 win 31088
    0x0000:  4520 002c da5d 4000 3406 1e1d 3ed2 fb53
    0x0010:  0a01 0a0b 61da dbd8 d800 357c f828 8275
    0x0020:  5018 7970 1a58 0000 0800 0000 0000
1450840574.666496 IP 10.1.10.11.56280 > b31.netatmo.net.25050: P 443:447(4) ack 45 win 2956
    0x0000:  4500 002c 4bce 0000 fe06 22cc 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 8275 d800 3580
    0x0020:  5018 0b8c 8738 0000 0900 0000 0000
1450840574.770808 IP b31.netatmo.net.25050 > 10.1.10.11.56280: F 45:45(0) ack 447 win 31088
    0x0000:  4520 0028 da5e 4000 3406 1e20 3ed2 fb53
    0x0010:  0a01 0a0b 61da dbd8 d800 3580 f828 8279
    0x0020:  5011 7970 225b 0000 0000 0000 0000
1450840574.870753 IP 10.1.10.11.56280 > b31.netatmo.net.25050: . ack 46 win 2955
    0x0000:  4500 0028 7d95 0000 fe06 f108 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 8279 d800 3581
    0x0020:  5010 0b8b 9040 0000 0000 0000 0000
1450840574.871685 IP 10.1.10.11.56280 > b31.netatmo.net.25050: F 447:447(0) ack 46 win 2955
    0x0000:  4500 0028 0a80 0000 fe06 641e 0a01 0a0b
    0x0010:  3ed2 fb53 dbd8 61da f828 8279 d800 3581
    0x0020:  5011 0b8b 903f 0000 0000 0000 0000
1450840574.976182 IP b31.netatmo.net.25050 > 10.1.10.11.56280: . ack 448 win 31088
    0x0000:  4520 0028 cf38 4000 3406 2946 3ed2 fb53
    0x0010:  0a01 0a0b 61da dbd8 d800 3581 f828 827a
    0x0020:  5010 7970 225a 0000 0000 0000 0000"""
        print TCPPacket.lines2packets(tcp_lines)

    main()
