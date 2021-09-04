#!/usr/bin/env python3

#
# loki-proxy-am
#
# These codes are licensed under CC0.
# http://creativecommons.org/publicdomain/zero/1.0/deed.ja
#

import argparse
import base64
import http.server
import json
import urllib.error
import urllib.request
import ssl
import sys

DEFAULT_CONFIG    = 'config.json'
DEFAULT_ADDRESS   = '127.0.0.1'
DEFAULT_PORT      = 3101
DEFAULT_LOG_LEVEL = 'info'

CONFIG = {}
LOG_LEVEL = 0

def set_log_level(name):
    global LOG_LEVEL
    if name == 'error':
        LOG_LEVEL = 3
    if name == 'info':
        LOG_LEVEL = 6
    if name == 'debug':
        LOG_LEVEL = 7

def log_error(msg):
    if LOG_LEVEL >= 3:
        print(msg)

def log_info(msg):
    if LOG_LEVEL >= 6:
        print(msg)

def log_debug(msg):
    if LOG_LEVEL >= 7:
        print(msg)

class Handler(http.server.BaseHTTPRequestHandler):
    def req_json(self):
        content_type = self.headers.get('content-type', '')
        content_length = int(self.headers.get('content-length',  0))
        log_info('POST {} from={} content-type={} content-length={}'.format(
            self.path,
            self.client_address,
            content_type,
            content_length,
        ))
        if self.path.endswith('/api/v1/alerts') and content_type == 'application/json':
            return json.loads(self.rfile.read(content_length).decode('utf-8'))

    def send_to_AMs(self, alerts):
        ret = {
            'code': 502,  # Bad Gateway
            'data': {},
        }
        alertmanagers = CONFIG.get('alertmanagers', [])
        for am in alertmanagers:
            context = None
            headers = {
                'Content-Type': 'application/json',
            }
            scheme = am.get('scheme', 'http')
            if scheme == 'https':
                context = ssl.create_default_context()
                if 'tls_config' in am:
                    if am['tls_config'].get('insecure_skip_verify', False):
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
            else:
                scheme = 'http'
            if 'basic_auth' in am:
                username = am['basic_auth'].get('username')
                password = am['basic_auth'].get('password')
                if username and password:
                    user_pass = '{}:{}'.format(username, password).encode('utf-8')
                    user_pass = base64.b64encode(user_pass).decode('utf-8')
                    headers['Authorization'] = 'Basic ' + user_pass
            for host in am.get('hosts', []):
                url = '{}://{}{}'.format(scheme, host, self.path)
                try:
                    req = urllib.request.Request(
                        url,
                        headers=headers,
                        method='POST',
                        data=json.dumps(alerts).encode('utf-8'),
                    )
                    with urllib.request.urlopen(req, context=context) as res:
                        res_code = res.getcode()
                        res_data = json.loads(res.read())
                        log_debug('POST {} res-code={} res-data{}'.format(url, res_code, res_data))
                        if ret['code'] != 200:
                            ret['code'] = res_code
                            ret['data'] = res_data
                except urllib.error.URLError as exc:
                    log_error('POST {} error={}'.format(url, str(exc)))
                    ret['data'] = { 'reason': str(exc) }
        return ret

    def do_POST(self):
        try:
            # parse request alerts data
            alerts = self.req_json()
            # append external labels
            for alert in alerts:
                if 'labels' in alert:
                    external_labels = CONFIG.get('external_labels', {})
                    for label_name, label_value in external_labels.items():
                        if not label_name in alert['labels']:
                            alert['labels'][label_name] = label_value
            # send alerts to AlertManagers
            ret = self.send_to_AMs(alerts)
        except Exception as exc:
            log_error('exception: {}'.format(str(exc)))
            ret = {
                'code': 500,
                'data': { 'reason': str(exc) },
            }
        # response data
        self.send_response(ret['code'])
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(ret['data']).encode('utf-8'))

    # disable logging
    def log_message(self, format, *args):
        pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        '-c', '--config',
        help='config file (default {})'.format(DEFAULT_CONFIG),
        type=str,
        default=DEFAULT_CONFIG,
    )
    p.add_argument(
        '-a', '--address',
        help='listen address (default {})'.format(DEFAULT_ADDRESS),
        type=str,
        default=DEFAULT_ADDRESS,
    )
    p.add_argument(
        '-p', '--port',
        help='listen port (default {})'.format(DEFAULT_PORT),
        type=int,
        default=DEFAULT_PORT,
    )
    p.add_argument(
        '--log-level',
        help='set log level (default {})'.format(DEFAULT_LOG_LEVEL),
        choices=['error', 'info', 'debug'],
        default=DEFAULT_LOG_LEVEL,
    )
    args = p.parse_args()
    set_log_level(args.log_level)
    with open(args.config, 'r') as f:
        global CONFIG
        CONFIG = json.load(f)
        # TODO: config check
    sa = (args.address, args.port)
    with http.server.HTTPServer(sa, Handler)  as sv:
        log_info('started http server on {}'.format(sa))
        sv.serve_forever()

if __name__ == '__main__':
    main()
