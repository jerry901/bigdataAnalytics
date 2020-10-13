#!/usr/bin/env python
""" Cisco ASA VPN Log Analysis Tool
Analyzes ASA VPN logs for anomalous behavior and outputs a list of suspicious
events and user connections.
"""
import argparse
import re
import csv
import math
from datetime import datetime
# requires maxmind geoip database and library
# http://dev.maxmind.com/geoip/legacy/install/city/
import GeoIP

GEOIP_DB = 'GeoLiteCity.dat'
TIME_FMT = '%b %d, %Y %I:%M:%S %p %Z'
CONNECT = (r'.*&gt; User &lt;(?P<user>.*)&gt; IP &lt;(?P<external>.*)&gt; '
           r'Address &lt;(?P<internal>.*)&gt; assigned to session')
DISCONNECT = (r'.*&gt; User &lt;(?P<user>.*)&gt; IP &lt;(?P<external>.*)&gt; '
              r'SVC closing connection: (?P<reason>.*)')
HEADERS = ['timestamp', 'user', 'key', 'internal', 'external', 'reason',
           'geoip_cc', 'geoip_lat', 'geoip_long', 'haversine']


class Rule(object):
    """ Basic rule object class """
    def __init__(self, key, title, regex):
        self.key = key
        self.title = title
        self.regex = re.compile(regex)


class Event(object):
    """ Basic event class for handling log events """
    _rules = []
    _rules.append(Rule('ASA-4-722051', 'connect', CONNECT))
    _rules.append(Rule('ASA-5-722037', 'disconnect', DISCONNECT))

    def __init__(self, raw_event):
        for rule in self._rules:
            if rule.key in raw_event:
                self._match_rule(rule, raw_event)
                self.key = rule.title

    def _match_rule(self, rule, raw_event):
        match = rule.regex.match(raw_event)
        for key, value in match.groupdict().iteritems():
            setattr(self, key, value)

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return repr(self.__dict__)


def distance(origin, destination):
    """ Haversine distance calculation
    https://gist.github.com/rochacbruno/2883505
    """
    lat1, lon1 = origin
    lat2, lon2 = destination
    radius = 6371  # km

    dlat = math.radians(lat2-lat1)
    dlon = math.radians(lon2-lon1)
    a = math.sin(dlat/2) * math.sin(dlat/2) + math.cos(math.radians(lat1)) \
        * math.cos(math.radians(lat2)) * math.sin(dlon/2) * math.sin(dlon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    d = radius * c

    return d


def read_csv(file):
    """ Reads a CSV file and returns the header and rows """
    with file:
        reader = csv.reader(file)

        header = reader.next()
        rows = list(reader)

    return header, rows


def write_csv(file, events):
    """ Write a list of events to a CSV file """
    with file:
        writer = csv.DictWriter(file, HEADERS)
        writer.writeheader()

        for event in events:
            writer.writerow(event.__dict__)


def normalize(header, rows):
    """ Normalizes the data """
    events = []
    for row in rows:
        timestamp = row[header.index('ReceiveTime')]
        raw_event = row[header.index('RawMessage')]

        event = Event(raw_event)
        event.timestamp = datetime.strptime(timestamp, TIME_FMT)

        events.append(event)

    return sorted(events, key=lambda x: (x.user, x.timestamp))


def analyze(events):
    """ Main event analysis loops """
    gi = GeoIP.open(GEOIP_DB, GeoIP.GEOIP_STANDARD)

    for i, event in enumerate(events):
        # calculate the geoip information
        if event.external:
            record = gi.record_by_addr(event.external)
            events[i].geoip_cc = record['country_code']
            events[i].geoip_lat = record['latitude']
            events[i].geoip_long = record['longitude']

        # calculate the haversine distance
        if i > 0:
            if events[i].user == events[i-1].user:
                origin = (events[i-1].geoip_lat, events[i-1].geoip_long)
                destination = (events[i].geoip_lat, events[i].geoip_long)
                events[i].haversine = distance(origin, destination)
            else:
                events[i].haversine = 0.0
        else:
            events[i].haversine = 0.0

    return events


def parse_args():
    # parse commandline options
    parser = argparse.ArgumentParser()
    parser.add_argument('report', type=argparse.FileType('rb'),
                        help='csv report to parse')
    parser.add_argument('-o', '--out', default='out.csv',
                        type=argparse.FileType('w'),
                        help='csv report output file')
    return parser.parse_args()


def main():
    """ Main program function """
    args = parse_args()

    # read report
    header, rows = read_csv(args.report)

    # normalize event data
    events = normalize(header, rows)

    # perform analytics
    events = analyze(events)

    # write output
    write_csv(args.out, events)


if __name__ == '__main__':
    main()
