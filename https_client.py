#!/usr/bin/env python3

"""Perform simple HTTP GET requests over TLS."""

import socket
import argparse
import logging
import json
import sys

from tls_common import *
from tls_client import tls_query, DEFAULT_CLIENT_OPTIONS
from tls13_spec import TicketInfo, ClientOptions, ECHConfig


def http_get_req(hostname: str, path: str = '/') -> bytes:
    return b''.join([
        b'GET ',
        path.encode('ascii'),
        b' HTTP/1.1\r\nHost: ',
        hostname.encode('ascii'),
        b'\r\n\r\n',
    ])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description = 'Connect to an HTTPS server using TLS 1.3 and make a GET request.',
    )
    parser.add_argument('hostname')
    parser.add_argument('-p', '--port', type=int, default=443)
    parser.add_argument('-g', '--get', default='/', metavar='PATH',
        help='The path to make a GET request on; default is the root webpage "/"')
    parser.add_argument('-t', '--timeout', type=int, default=None)
    parser.add_argument('-s', '--store-ticket', type=argparse.FileType('w'), metavar='FILENAME',
        help='If a PSK reconnect ticket is received, save it to the given filename.')
    parser.add_argument('-u', '--use-ticket', type=argparse.FileType('r'), metavar='FILENAME',
        help='Attempt to use the ticket in the given filename to connect in PSK mode.')
    parser.add_argument('-r', '--remember-ech', type=argparse.FileType('w'), metavar='FILENAME')
    parser.add_argument('-e', '--use-ech', type=argparse.FileType('r'), metavar='FILENAME')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    if not args.quiet:
        logging.basicConfig(level=logging.INFO)

    options = DEFAULT_CLIENT_OPTIONS
    if args.use_ticket:
        ticket = TicketInfo.from_json(json.load(args.use_ticket))
        options = options.replace(
            send_psk=True,
            tickets=[ticket.uncreate()]
        )
    if args.use_ech:
        ech_config = ECHConfig.from_json(json.load(args.use_ech))
        options = options.replace(
            send_ech=True,
            ech_configs = [ech_config.variant],
        )

    resp, conn = tls_query(
        hostname = args.hostname,
        query = http_get_req(args.hostname, args.get),
        port = args.port,
        options = options,
        timeout = args.timeout,
    )

    if args.store_ticket:
        if conn.tickets:
            json.dump(conn.tickets[0].jsonify(), args.store_ticket)
            logger.info(f'got {len(conn.tickets)} tickets and saved one')
        else:
            logger.warning('did not receive any reconnect ticket to save')
    if args.remember_ech:
        if conn.ech_configs:
            json.dump(conn.ech_configs[0].jsonify(), args.remember_ech)
            logger.info(f'got {len(conn.ech_configs)} ech configs and saved one')
        else:
            logger.warning('did not receive any ECH config to save')

    if args.quiet:
        sys.stdout.buffer.write(resp)
        sys.stdout.buffer.flush()
    else:
        print()
        print("First five lines of response:")
        for line in resp.decode().split('\n')[:5]:
            print('   ', line.rstrip()[:72])
