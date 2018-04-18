#!/usr/bin/python3.6

### temporary imports

import sys

###

from lib import *

import argparse
import requests
import re

import warnings
warnings.filterwarnings("ignore")

from xml.etree import ElementTree as ET
from base64 import b64decode, b64encode

###

def log(m):
    print(f'[+] {m}')

ap = argparse.ArgumentParser(description = "Send all requests contained in an"\
        " XML file exported from burp and send each through a user defined "\
        " instance of burp. This aims to identify direct object reference"\
        " vulnerabilities.")

ap.add_argument('--input-file', '-i',
        dest = 'infile',
        action = 'store',
        help = 'XML items file exported from Burp')

# TODO: Define custom logging
# ap.add_argument('--log-file', '-l',
#         dest = 'logfile',
#         action = 'store',
#         help = 'File to store log information.')

ap.add_argument('--proxy-host', '-ph',
        dest = 'proxy_host',
        action = 'store',
        help = 'IP of upstream proxy.')

ap.add_argument('--proxy-port', '-pp',
        dest = 'proxy_port',
        action = 'store',
        help = 'Port of upstream proxy.')

# TODO: Allow cookies to be supplied via file name
ap.add_argument('--cookies', '-c',
        dest = 'cookies',
        action = 'store',
        default = 'none',
        choices = ['request', 'none'],
        help = 'Specify how to handle cookies.'\
                ' request indicates to use cookies as in the request.'\
                ' file indicates that cannon should use cookies from a file.'\
                ' none indicates that no cookies should be used.')

ap.add_argument('--verify-ssl', 
        dest = 'verify_ssl',
        action = 'store_true',
        default = False,
        help = 'Verify the server certificate if https is in use. Default: False')

ap.add_argument('--user-agent', '-ua',
        dest = 'user_agent',
        action = 'store',
        help = 'Specify a custom user agent string.')

# TODO: Delete this junk
fn = "/home/archangel/clients/microsoft/2018/testing/pod51500/all_items.xml"
args = f"-ua innocuous1.0 -i {fn} -ph 127.0.0.1 -pp 8080 -c none".split()

# TODO: Delete 'args' value here
args = ap.parse_args(args)
print(args)

# handle proxies
if args.proxy_host and args.proxy_port:
    proxies = {}
    for scheme in ['http','https']:
        proxies[scheme] = f"{scheme}://{args.proxy_host}:{args.proxy_port}"
else:
    proxies = None

# convenience is convenient
verify_ssl = args.verify_ssl

# TODO: Handle cookies from file

# handle the input file
doc = ET.parse(args.infile)

# iterate over the items
i = -1
for item in doc.findall('//item'):

    i += 1

    try:
        item = burp.Item(item)
    except:
        log(f"Unhandled exception while parsing item (#{i})")
        continue

    item.method = item.method.lower()

    if not dir(requests).count(item.method):
        log(f"Invalid method supplied ({item.method}). Skipping request #{i}...")
        continue

    # request keyword arguments
    kwargs = {'proxies':proxies}
    kwargs['verify'] = verify_ssl

    # TODO: Handle form data
    #   converting to a bytes object would likely be the best approach
    if item.body:
        kwargs['data'] = bytes(item.body,'ascii')

    # TODO: Handle cookies
    #   must handle cookies as well

    cookie_key = http.base.header_key_scan(item.headers,http.base.cookie_re)

    if args.cookies == 'request':
        kwargs['cookies'] = item.cookies
    elif args.cookies == 'none':
        kwargs['cookies'] = None

    # TODO: Handle user agent string
    if args.user_agent:

        ua_key = http.base.header_key_scan(item.headers,
                http.base.user_agent_re)

        if ua_key:
            item.headers[ua_key] = args.user_agent
        else:
            item.headers['User-Agent'] = args.user_agent

    # TODO: Handle request headers
    kwargs['headers'] = item.headers

    kwargs['allow_redirects'] = False

    # send the request
    r = requests.request(item.method,item.url,**kwargs)
