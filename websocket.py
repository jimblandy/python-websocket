"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

import sys, re, urlparse, socket, asyncore, threading, random

urlparse.uses_netloc.append("ws")
urlparse.uses_fragment.append("ws")

class WebSocket(object):
    def __init__(self, url, **kwargs):
        self.host, self.port, self.resource, self.secure = WebSocket._parse_url(url)
        self.protocol = kwargs.pop('protocol', None)
        self.cookie_jar = kwargs.pop('cookie_jar', None)
        self.onopen = kwargs.pop('onopen', None)
        self.onmessage = kwargs.pop('onmessage', None)
        self.onerror = kwargs.pop('onerror', None)
        self.onclose = kwargs.pop('onclose', None)
        trace = kwargs.pop('trace', False)
        if kwargs: raise ValueError('Unexpected argument(s): %s' % ', '.join(kwargs.values()))

        self._dispatcher = _Dispatcher(self, trace)

    def send(self, data,sync=False):
        self._dispatcher.write('\x00' + _utf8(data) + '\xff',sync)

    def close(self):
        self._dispatcher.handle_close()

    @classmethod
    def _parse_url(cls, url):
        p = urlparse.urlparse(url)

        if p.hostname:
            host = p.hostname
        else:
            raise ValueError('URL must be absolute')
    
        if p.fragment:
            raise ValueError('URL must not contain a fragment component')
    
        if p.scheme == 'ws':
            secure = False
            port = p.port or 80
        elif p.scheme == 'wss':
            raise NotImplementedError('Secure WebSocket not yet supported')
            # secure = True
            # port = p.port or 443
        else:
            raise ValueError('Invalid URL scheme')

        resource = p.path or u'/'
        if p.query: resource += u'?' + p.query
        return (host, port, resource, secure)



class WebSocketError(Exception):
    def _init_(self, value):
        self.value = value

    def _str_(self):
        return str(self.value)

class _Dispatcher(asyncore.dispatcher):
    def __init__(self, ws, trace=False):
        self.trace = trace

        self.lock = threading.Lock() #threadsafe addon
        
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((ws.host, ws.port))
        self.isopen = True
        
        self.ws = ws
        self._read_buffer = ''
        self._write_buffer = ''
        
        if self.ws.port != 80:
            hostport = '%s:%d' % (self.ws.host, self.ws.port)
        else:
            hostport = self.ws.host
        
        self.key = _Key()

        fields = [
            'Upgrade: WebSocket',
            'Connection: Upgrade',
            'Host: ' + hostport,
            'Origin: http://' + hostport
        ]
        fields += self.key.challenge_headers()
        if self.ws.protocol: fields['Sec-WebSocket-Protocol'] = self.ws.protocol
        if self.ws.cookie_jar:
            cookies = filter(lambda c: _cookie_for_domain(c, _eff_host(self.ws.host)) and \
                             _cookie_for_path(c, self.ws.resource) and \
                             not c.is_expired(), self.ws.cookie_jar)
            
            for cookie in cookies:
                fields.append('Cookie: %s=%s' % (cookie.name, cookie.value))
        
        self.write(_utf8('GET %s HTTP/1.1\r\n%s\r\n\r\n'
                         % (self.ws.resource,
                            '\r\n'.join(fields)))
                   + self.key.challenge_content())

        self._current_read_handler = self._handle_header

    def log(self, message):
        if self.trace:
            print message

    def handle_expt(self):
        self.handle_error()

    def handle_error(self):
        self.close()
        t, e, trace = sys.exc_info()
        if self.ws.onerror:
            self.ws.onerror(e)
        else:
            asyncore.dispatcher.handle_error(self)

    def handle_close(self):
        self.close()
        self.isopen = False
        if self.ws.onclose:
            self.ws.onclose()

    def handle_connect (self):
        pass
        
    def handle_read(self):
        data = self.recv(4096)
        self.log('received: %r' % (data,))
        self._read_buffer += data
        while self._read_buffer:
            handler = self._current_read_handler
            consumed = handler(self._read_buffer)
            if not consumed:
                self.log('rejected: handler %s rejected %r' 
                         % (handler.handler_name, self._read_buffer))
                return
            self.log('consumed: handler %s consumed %r' 
                     % (handler.handler_name, self._read_buffer[:consumed]))
            self._read_buffer = self._read_buffer[consumed:]

    def handle_write(self):
        with self.lock: #threadsafe addon
            sent = self.send(self._write_buffer)
            self.log('sent: %r' % (self._write_buffer[:sent],))
            self._write_buffer = self._write_buffer[sent:]

    def writable(self):
        with self.lock: #threadsafe addon
            return len(self._write_buffer) > 0

    def write(self, data,sync=False):
        with self.lock: #threadsafe addon
            self._write_buffer += data # TODO: separate buffer for handshake from data to
                                  # prevent mix-up when send() is called before
                                  # handshake is complete?
        if sync:
          self.handle_write()

    def _handle_header(self, data):
        pos = data.find('\r\n\r\n')
        if pos < 0: return False
        header = data[:pos]
        start_line, fields = _parse_http_header(header)
        if start_line != 'HTTP/1.1 101 WebSocket Protocol Handshake' or \
           fields.get('Connection', None) != 'Upgrade' or \
           fields.get('Upgrade', None) != 'WebSocket':
            raise WebSocketError('Invalid server handshake')
        self.key.check_server_fields(fields)
        if self.key.need_server_content:
            self._current_read_handler = self._handle_server_digest
        else:
            self._current_read_handler = self._handle_frame
        return pos + 4

    _handle_header.handler_name = 'header'

    def _handle_server_digest(self, data):
        if len(data) < 16: return False
        self.key.check_server_body(data[:16])
        if self.ws.onopen:
            self.ws.onopen()
        self._current_read_handler = self._handle_frame
        return 16

    _handle_server_digest.handler_name = 'server digest'

    def _handle_frame(self, data):
        pos = data.find('\xff')
        if pos < 0: return False
        if data[0] != '\x00':
            raise WebSocketError('WebSocket stream error')
        frame = data[1:pos]
        if self.ws.onmessage:
            self.ws.onmessage(frame)
        # TODO: else raise WebSocketError('No message handler defined')
        return pos + 1

    _handle_frame.handler_name = 'frame'

_IPV4_RE = re.compile(r'\.\d+$')
_PATH_SEP = re.compile(r'/+')

def _parse_http_header(header):
    def split_field(field):
        k, v = field.split(':', 1)
        return (k, v.strip())

    lines = header.strip().split('\r\n')
    if len(lines) > 0:
        start_line = lines[0]
    else:
        start_line = None
        
    return (start_line, dict(map(split_field, lines[1:])))

def _eff_host(host):
    if host.find('.') == -1 and not _IPV4_RE.search(host):
        return host + '.local'
    return host

def _cookie_for_path(cookie, path):
    if not cookie.path or path == '' or path == '/':
        return True
    path = _PATH_SEP.split(path)[1:]
    cookie_path = _PATH_SEP.split(cookie.path)[1:]
    for p1, p2 in map(lambda *ps: ps, path, cookie_path):
        if p1 == None:
            return True
        elif p1 != p2:
            return False

    return True

def _cookie_for_domain(cookie, domain):
    if not cookie.domain:
        return True
    elif cookie.domain[0] == '.':
        return domain.endswith(cookie.domain)
    else:
        return cookie.domain == domain

def _utf8(s):
    return s.encode('utf-8')

class _Key():
    def __init__(self):
        self.spaces_1 = 5 # random.randint(1, 12)
        self.spaces_2 = 9 # random.randint(1, 12)
        max_1 = 4294967295 / self.spaces_1
        max_2 = 4294967295 / self.spaces_2
        self.number_1 = 777007543 # random.randint(0, max_1)
        self.number_2 = 114997259 # random.randint(0, max_2)
        self.product_1 = self.number_1 * self.spaces_1
        self.product_2 = self.number_2 * self.spaces_2
        self.key_1 = ''.join(_Key.spaces(_Key.fluff(list(str(self.product_1))),
                                         self.spaces_1))
        self.key_2 = ''.join(_Key.spaces(_Key.fluff(list(str(self.product_2))),
                                         self.spaces_2))
        self.key_3 = ''.join((chr(random.randint(0, 255)) for i in range(8)))

    def challenge_headers(self):
        return ['Sec-WebSocket-Key1: ' + self.key_1,
                'Sec-WebSocket-Key2: ' + self.key_2]
    def challenge_content(self):
        return self.key_3

    def check_server_fields(self, fields): pass
    def check_server_body(self, body): pass
    def need_server_content(self): return True


    mixin_chars = map(chr, range(0x21, 0x2f) + range(0x3a, 0x7e))

    @classmethod
    def fluff(cls, key):
        for i in xrange(random.randint(1, 12)):
            pos = random.randint(0, len(key))
            key[pos:pos] = random.choice(_Key.mixin_chars)
        return key

    @classmethod
    def spaces(cls, key, spaces):
        for i in xrange(spaces):
            pos = random.randint(1, len(key) - 1)
            key[pos:pos] = ' '
        return key
