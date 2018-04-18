from types import MethodType
from base64 import b64encode, b64decode
from .. import http

def trim_val(val,maximum=80):
    """Trim a string length down and suffix a '...'"""

    if type(val) == str and len(val) > maximum:
        val = val[0:(maximum-1)]+"..."

    return val

def trim_vals(val):
    """Trim values in a dictionary or list."""

    tp = type(val)

    if tp == dict:
        nv = {}

        for k,v in val.items():
            nv[k] = trim_val(v)

    elif tp == list:
        nv = []

        for v in val:
            nv.append(trim_val(val))

    return nv

class Item:

    def __init__(s, ele):
        """Initialize a burp item from an xml.etree.ElementTree.Element"""\
        """ object"""

        # set the simple attributes that do not require extensive processing
        # TODO: might want to do some exception handling here; renegade
        attrs = ['url', 'method', 'path', 'extension', 'status']
        for attr in attrs:
            setattr(s,attr,ele.find(f'./{attr}').text)

        # extract the ip address and hostname
        host = ele.find('./host')
        s.host = host.text
        s.ip = host.attrib['ip']

        # determine if https should be used in the request
        if ele.find('./protocol').text == 'https':
            https = True
        else:
            https = False

        s.https = https

        # extract the request
        req = ele.find('./request')
        if req.attrib['base64'] == 'true':
            b64_encoded = True
        else:
            b64_encoded = False

        s.base64_encoded = b64_encoded

        if s.base64_encoded:

            try:
                s.request = b64decode(req.text).decode('utf-8')
                encoding = 'utf-8'
            except UnicodeDecodeError:
                s.request = b64decode(req.text).decode('ascii')
                encoding = 'ascii'

        else:

            s.request = req.text

        # handle the headers
        s.headers, s.body = http.base.parse(s.request)

        # determine the encoding
        encoding = http.base.charset_scan(s.headers)

        cookie_key = http.base.header_key_scan(s.headers,
                http.base.cookie_re)

        if cookie_key:
            s.cookies = http.base.cookie_parse(s.headers[cookie_key])
            del(s.headers[cookie_key])
        else:
            s.cookies = None

        if len(s.body) < 1:
            s.body = None

    def __str__(s):
        """Format and return the object for legible printing"""

        out = [f"{type(s)} #{id(s)}"]
        attrs = sorted([a for a in dir(s) if a[0] != '_'])
        for attr in attrs:

            val = getattr(s,attr)

            tp = type(val)

            if tp == MethodType:
                continue
            elif tp == dict or tp == list:
                val = trim_vals(val)
            else:
                val = trim_val(val)

            out.append(f"\t{attr}: {val}")

        return "\n".join(out)

    def to_json(self):
        pass

