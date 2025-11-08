#!/usr/bin/env python3

import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import time
import re
import logging
import logging.handlers
import argparse
import socket
import yaml
import fnmatch

import dns
import dns.flags
import dns.opcode
import dns.rrset
import dns.rcode
import dns.update
import dns.message
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring

from dns import rdataclass, rdatatype

from botocore.credentials import Credentials

from jsonschema import validate

from pprint import pprint
from inspect import getmembers
from types import FunctionType

from server import Server
from route53 import Route53Client

VERSION = '0.1'

logger = logging.getLogger("")
args = None
fqdn_regex = "^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$"
schema = {
    "type": "object",
    "properties": {
        "zones": {
            "description": "Zone declarations",
            "type": "object",
            "patternProperties": {
                fqdn_regex: {
                    "type": "object",
                    "properties": {
                        "credentials": {
                            "type": "object",
                            "properties": {
                                "access_key": { "type": "string" },
                                "secret_key": { "type": "string" }
                            },
                            "required": [ "access_key", "secret_key" ]
                        }
                    },
                    "required": [ "credentials" ]
                }
            }
        },
        "clients": {
            "description": "Client declarations",
            "type": "object",
            "patternProperties": {
                fqdn_regex: {
                    "type": "object",
                    "properties": {
                        "secret": { "type": "string", "pattern": "[^-A-Za-z0-9+/=]|=[^=]|={3,}$" },
                        "domains": { "type": "array", "items": { "type": "string", "pattern": fqdn_regex } },
                        "aliasdomains": {
                            "anyOf": [
                                {
                                    "type": "string", "pattern": fqdn_regex
                                },
                                {
                                    "type": "object", "patternProperties": { fqdn_regex: { "type": "string", "pattern": fqdn_regex } }
                                }
                            ]
                        }
                    },
                    "required": [ "secret" ]
                }
            }
        }
    },
    "required": [ "zones", "clients" ]
}

def attributes(obj):
    disallowed_names = {
      name for name, value in getmembers(type(obj))
        if isinstance(value, FunctionType)}
    return {
      name: getattr(obj, name) for name in dir(obj)
        if name[0] != '_' and name not in disallowed_names and hasattr(obj, name)}

def print_attributes(obj):
    pprint(attributes(obj))

class AcmeProxyConfig(object):
    def __init__(self, source=''):
        if not source:
            raise Exception('No configuration file source specified')

        self._source = source
        self._config = self._load_config_file()
        self._keyring = self._load_keyring()
        self._zones = self._config['zones'] # shorthand..
        self._clients = self._config['clients'] # shorthand..

    @property
    def keyring(self):
        return self._keyring

    @property
    def zones(self):
        return self._zones

    @property
    def clients(self):
        return self._clients

    def _load_config_file(self):
        with open(self._source, 'r') as stream:
            result = yaml.safe_load(stream)
            validate(result, schema)
            logger.debug('Read configuration from %s successfully.' % (self._source))
            return result

    def _load_keyring(self):
        # Read all preshared keys, convert them to the format
        # dnspython understands so it can be passed directly to
        # the dns.message.to_wire() function.
        data = dict([(k_v[0] + '.', k_v[1]['secret']) for k_v in list(self._config['clients'].items())])
        return dns.tsigkeyring.from_text(data)

    def _get_closest_zone_for(self, fqdn):
        result = None
        zones = list(reversed(sorted(list(self._zones.keys()), key=len)))

        while fqdn and not result:
            # Produce the iterable for each searc before the filter
            result = next(iter([x for x in zones if x == fqdn]), None)
            fqdn = fqdn.partition('.')[-1]

        return result

    def get_aws_credentials_for(self, fqdn):
        zonename = self._get_closest_zone_for(fqdn)
        zone = self._zones.get(zonename, None)
        if zone is None:
            raise Exception('No zone available for %s?!' % fqdn)

        if not 'credentials' in zone:
            raise Exception('Zone "%s" has no credentials node?!' % zonename)

        if type(zone['credentials']) is not dict:
            raise Exception('Zone "%s" has invalid credentials data?!' % zonename)

        if not bool(zone['credentials']):
            raise Exception('Zone "%s" has no credentials defined?!' % zonename)

        return zone['credentials']

    def get_client(self, name):
        return self.clients.get(name, None)

    def get_domains_for(self, client):
        c = self.get_client(client)
        if c is not None:
            return c.get('domains', [])
        return []

    def get_aliasdomain_for(self, client, domain):
        # If domain is part of a managed zone, avoid aliasing
        if self._get_closest_zone_for(domain):
            return None
        c = self.get_client(client)
        if c is None:
            return None
        data = c.get('aliasdomains', None)
        if isinstance(data, dict) and domain in data:
            return data[domain]
        elif isinstance(data, dict) and '*' in data:
            return data['*']
        elif isinstance(data, dict):
            return None
        return data

class AcmeProxy(Server):
    def __init__(self, config=None, **kwargs):
        self.config = config
        super(AcmeProxy, self).__init__(**kwargs)

    def _domain_matches(self, domain, domains):
        for d in domains:
             if fnmatch.fnmatch(domain, d):
                return True
        return False

    def handle_query_in_soa(self, query, reply):
        q = query.question
        text = '%s. admin.dummy. 1 60 60 86400 86400' % socket.gethostname()
        soa = dns.rrset.from_text(q.name, 5, 'IN', 'SOA', text)
        reply.flags |= dns.flags.AA
        reply.answer.append(soa)
        reply.set_rcode(dns.rcode.NOERROR)
        return

    def handle_update(self, query, reply):
        value = None
        m = query.message
        k = '.'.join([key.decode('utf-8') if isinstance(key, bytes) else key for key in query.keyname[:-1]])
        c = self.config.get_client(k)

        if c is None:
            logger.error('Refusing UPDATE message from unknown client: %s' % query.keyname)
            reply.set_rcode(dns.rcode.REFUSED)
            return

        if len(m.authority) != 1:
            logger.error('Refusing UPDATE message with multiple recordset.')
            reply.set_rcode(dns.rcode.REFUSED)
            return

        rrset = m.authority[0]
        name = rrset.name.to_text()[:-1] #< Remove final dot (.)

        if not name.startswith('_acme-challenge.'):
            logger.error('Invalid update request for %s: not a valid ACME challenge record.' % name)
            reply.set_rcode(dns.rcode.REFUSED)
            return

        # Only support rdatatype TXT for acme-challenges
        if rrset.rdtype != dns.rdatatype.TXT:
            logger.error('Refusing UPDATE rrset with TYPE!=TXT.')
            reply.set_rcode(dns.rcode.REFUSED)
            return

        if len(rrset.items) > 1:
            logger.error('Refusing UPDATE message with multiple (%d) records.' % len(rrset.items))
            reply.set_rcode(dns.rcode.REFUSED)
            return
        elif len(rrset.items) == 1:
            #Some stuff has changed from py2 to py3
            #Legacy times rrset was a list and not a dict
            value = list(rrset.items.keys())[0].strings

            if value is None or len(value) != 1:
                logger.error('Refusing UPDATE message with non-TXT value.')
                reply.set_rcode(dns.rcode.REFUSED)
                return

            #We need to decode the value given that it comes as a byte string
            value = value[0].decode('utf-8')

        cfqdn = socket.getfqdn(query.address)
        logger.debug('Received update for: %s from: (%s/%s)' % (rrset.name, query.address, cfqdn))

        rfqdn = name.replace('_acme-challenge.', '')
        if rfqdn != cfqdn and not self._domain_matches(rfqdn, self.config.get_domains_for(k)):
            logger.warning('Client %s not allowed to make requests for %s (client fqdn: %s)' % (k, rfqdn, cfqdn))
            reply.set_rcode(dns.rcode.REFUSED)
            return

        aliasdomain = self.config.get_aliasdomain_for(k, rfqdn)
        if not aliasdomain is None:
            logger.debug('Relaying received update for %s to aliasdomain: %s' % (name, aliasdomain))
            name = aliasdomain

        credentials = self.config.get_aws_credentials_for(name)
        r53 = Route53Client(credentials['access_key'], credentials['secret_key'])

        if rrset.deleting == dns.rdataclass.ANY:
            logging.debug('Deleting %s' % name)
            r53.delete_record(name)
        else:
            logging.debug('Creating %s %s' % (name, value))
            r53.create_record(name, value)

        reply.set_rcode(dns.rcode.NOERROR)
        return

def create_args_parser():
    defconf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'acmeproxy.yaml')
    parser = argparse.ArgumentParser(description='AcmeProxy DNS Server v%s.' % VERSION)
    parser.add_argument('--config',
                        default=defconf,
                        type=str,
                        help='The configuration file')
    parser.add_argument('-d', '--debug',
                        default=logging.WARNING,
                        action='store_const',
                        dest='loglevel',
                        const=logging.DEBUG,
                        help='Enable DEBUG logging.')
    parser.add_argument('-v', '--verbose',
                        action='store_const',
                        dest='loglevel',
                        const=logging.INFO,
                        help='Enable INFO logging.')
    parser.add_argument('--port',
                        default=5053,
                        type=int,
                        help='The port to listen on.')
    parser.add_argument('--address',
                        default='127.0.0.1',
                        type=str,
                        help='The address to listen on.')
    parser.add_argument('--tcp',
                        action='store_true',
                        default=True,
                        help='Listen to TCP connections.')
    parser.add_argument('--udp',
                        action='store_true',
                        default=True,
                        help='Listen to UDP datagrams.')
    parser.add_argument('-V', '--version',
                        action='store_true',
                        help='Show version and exit')
    return parser

def logging_setup():
    logFormatter = logging.Formatter('%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s')
    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(args.loglevel)
    consoleHandler.setFormatter(logFormatter)
    logging.getLogger().setLevel(args.loglevel)
    logging.getLogger().addHandler(consoleHandler)

    #for name in logging.root.manager.loggerDict:
    #    logger.debug("Configuring %s.." % name)
    #    logging.getLogger(name).setLevel(args.loglevel)

def main():
    config = AcmeProxyConfig(args.config)
    server = AcmeProxy(keyring=config.keyring, address=args.address,
                       port=args.port, enable_tcp=args.tcp,
                       enable_udp=args.udp)
    server.config = config

    server.start()
    logger.info('Acmeproxy version %s started.' % (VERSION))

    try:
        # TODO: Implement signal handling and maybe notify sockets
        #        in order to have better integration with systemd.
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        logger.info('User interrupt, shutting down servers')
        server.stop()

if __name__ == '__main__':
    parser = create_args_parser()
    args = parser.parse_args()

    logging_setup()

    if args.version:
        print(('acmeproxy version %s' % VERSION))
        sys.exit(0)

    try:
        main()
    except Exception as e:
        logger.error('Service initialization failed: %s' % e, exc_info=True)
        sys.exit(255) #< Abnormal termination..

    sys.exit(0) #< Normal termination..

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
