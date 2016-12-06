# autotune.py - Find the best airFiber settings for a given link
# Copyright 2016 Ian Weller <ianweller@buttslol.net>
#
# This program is free software. It comes without any warranty, to the extent
# permitted by applicable law. You can redistribute it and/or modify it under
# the terms of the Do What The Fuck You Want To Public License, Version 2, as
# published by Sam Hocevar. See http://www.wtfpl.net/ for more details. 


import paramiko
import requests
import sched
import statistics
import time


def capacity(url, duration):
    """
    Analyzes theoretical capacity as measured by the radio.

    {url}/afstats.cgi is accessed every second for {duration} seconds.

    Response is something like {"rx": {"mean": 0, "stdev", 0}, "tx": ...}
    """

    # get a session ID first, *then* log in
    # https://community.ubnt.com/t5/-/-/m-p/615771/highlight/true#M34419
    # (ubnt forums notoriously change, https://archive.is/7OAuQ)
    r = requests.get(url + '/login.cgi')
    cookies = r.cookies
    requests.post(url + '/login.cgi', cookies=cookies,
                  allow_redirects=False,
                  files={'username': (None, 'ubnt'),
                         'password': (None, 'ubnt'),
                         'uri': (None, '/afstats.cgi')})

    tx_samples = []
    rx_samples = []

    def fetch_stats():
        r = requests.get(url + '/afstats.cgi', cookies=cookies).json()
        tx_samples.append(int(r['interfaces'][0]['stats']['txcapacity']))
        rx_samples.append(int(r['interfaces'][0]['stats']['rxcapacity']))

    s = sched.scheduler()
    for i in range(duration):
        s.enter(i, 0, fetch_stats)
    s.run()

    return {'tx': {'mean': statistics.mean(tx_samples),
                   'stdev': statistics.stdev(tx_samples)},
            'rx': {'mean': statistics.mean(rx_samples),
                   'stdev': statistics.stdev(rx_samples)}}


class ZeroCapacityException(Exception):
    """
    Raised when there is zero capacity (i.e. the remote radio cannot be reached
    because there is no link).
    """

    pass


def sleep_until_ready(urls):
    start = time.monotonic()
    for url in urls:
        while True:
            if time.monotonic() > start + 300:
                raise ZeroCapacityException()
            try:
                requests.get(url, timeout=5)
                break
            except requests.exceptions.Timeout:
                pass


def set_radio(hosts, txpowers, rfrates):
    """
    All arguments are two-tuples. Specify the remote host first!

    hosts: hostname/IP address of the radio (SSH port is assumed to be 22,
        username and password are assumed to be ubnt)
    txpowers: int where -10 <= x <= 26
    rfrates: str in 1x 2x 4x 6x 8x 10x
    """

    if (not all(x in ('1x', '2x', '4x', '6x', '8x', '10x') for x in rfrates)
            or not all(-10 <= x <= 26 for x in txpowers)):
        raise Exception('Invalid input. Sorry that this message is useless')

    for host, txpower, rfrate in zip(hosts, txpowers, rfrates):
        client = paramiko.SSHClient()
        # XXX AutoAddPolicy is inherently insecure!
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        # XXX Hardcoding passwords is inherently insecure!
        client.connect(host, username='ubnt', password='ubnt')
        _, stdout, _ = client.exec_command(
            'grep ^radio.1.antenna.gain /tmp/system.cfg | cut -d = -f 2')
        txpower += int(stdout.read().strip())

        # XXX Running commands like this can be insecure!
        # Verify that only variables that have been checked are used here
        cmd = r"sed -i 's/^\({}\)=.*$/\1={}/' /tmp/system.cfg"
        for k, v in (('radio.1.txpower', str(txpower)),
                     ('radio.1.rate.auto', 'disabled'),
                     ('radio.1.rate', rfrate),
                     ('radio.1.rfrate', rfrate)):
            # doesn't work unless you read stdout
            client.exec_command(cmd.format(k, v))[1].read()

        client.exec_command('cfgmtd -f /tmp/system.cfg -w')[1].read()
        client.exec_command('reboot')
        client.close()


if __name__ == '__main__':
    # reed pls fix
    set_radio(('10.255.255.13', '10.255.255.12'),
              (17, 24), ('4x', '4x'))
    sleep_until_ready(('http://10.255.255.13', 'http://10.255.255.12'))
    print(capacity('http://10.255.255.13', 15))
