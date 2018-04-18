import re

cookie_re  = re.compile('^cookie$',re.I)
user_agent_re = re.compile('^user\-agent',re.I)
header_re = '(?P<name>^.+):\s(?P<value>.+$)'
content_type_re = re.compile('^content\-type$',re.I)

def parse(http):
    """Parse an HTTP request or response delimited by a crlf+crlf sequence"""

    # split the http into headers and body
    headers, body = http.split('\r\n\r\n')

    # parse the headers
    headers = header_parse(headers)

    return headers, body

def check_header_format(headers):

    if type(headers) == str:
        headers = header_parse(headers)

    return headers

def charset_scan(headers,ct_re = content_type_re):
    """Scan supplied headers and determine charset encoding"""

    headers = check_header_format(headers)
    key = header_key_scan(headers,ct_re)

    if key:
        if re.search(r'utf',headers[key],re.I):
            out = 'utf-8'
        elif re.search(r'ascii',headers[key],re.I):
            out = 'ascii'
    else:
        out = 'utf-8'

    return out

def header_key_scan(headers,h_re):
    """Scan supplied headers and return a matching key or None"""

    h_key = None

    headers = check_header_format(headers)

    for k in headers.keys():
        if re.match(h_re,k):
            h_key = k
            break

    return h_key

def cookie_parse(cookie_string):
    """Parse a raw string of cookies into a dictionary"""

    # new cookies
    n_cookies = {}
    cookies = cookie_string.split('; ')

    for cookie in cookies:

        # identify first instance of =
        i = 0
        while cookie[i] != '=':
            i += 1

        # cookie name
        n = cookie[0:i]

        # cookie value
        v = cookie[(i+1):]

        n_cookies[n] = v


    return n_cookies

def header_parse(headers,header_re = header_re):
    """Parse a block of HTTP headers delimited by crlf sequences"""

    # compile the re for efficiency
    hre = re.compile(header_re)

    # capture the headers in a dictionary
    hdict = {}

    # iterate over all the headers, skipping the first since it is likely the
    # method line
    for raw_header in headers.split('\r\n')[1:]:
        m = re.match(hre,raw_header)
        groups = m.groupdict()
        hdict[groups['name']] = groups['value']

    return hdict
