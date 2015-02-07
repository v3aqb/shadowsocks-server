#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
# Copyright (c) 2014 v3aqb
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import with_statement


__version__ = '1.0.0'

import sys
if sys.version_info < (2, 6):
    import simplejson as json
else:
    import json

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import errno
import socket
import thread
import threading
import SocketServer
import struct
import logging
import getopt
import encrypt
import os
import urlparse
from util import create_connection, getaddrinfo, parse_hostport, get_ip_address


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ShadowsocksServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, serverinfo, RequestHandlerClass, bind_and_activate=True):
        self.serverinfo = serverinfo
        p = urlparse.urlparse(serverinfo)
        encrypt.check(p.password, p.username)
        self.key, self.method = p.password, p.username
        self.aports = [int(k) for k in urlparse.parse_qs(p.query).get('ports', [''])[0].split(',') if k.isdigit()]
        reverse = urlparse.parse_qs(p.query).get('reverse', [''])[0]
        self.reverse = parse_hostport(reverse) if reverse else None

        addrs = getaddrinfo(p.hostname, p.port)
        if not addrs:
            raise ValueError('cant resolve listen address')
        self.address_family = addrs[0][0]
        server_address = (p.hostname, p.port)
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)

    def server_activate(self):
        self.socket.listen(self.request_queue_size)


class Socks5Server(SocketServer.StreamRequestHandler):
    timeout = 20
    bufsize = 8192

    def handle_tcp(self, local, remote, timeout=60):
        def _io_copy(dest, source, timeout, cipher):
            try:
                dest.settimeout(timeout)
                source.settimeout(timeout)
                while 1:
                    data = source.recv(self.bufsize)
                    if not data:
                        break
                    dest.sendall(cipher(data))
            except socket.timeout:
                pass
            except (IOError, OSError) as e:
                if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                    raise
                if e.args[0] in (errno.EBADF,):
                    return
            finally:
                for sock in (dest, source):
                    try:
                        sock.close()
                    except (IOError, OSError):
                        pass
        thread.start_new_thread(_io_copy, (remote.dup(), local.dup(), timeout, self.decrypt))
        _io_copy(local, remote, timeout, self.encrypt)

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def _request_is_loopback(self, req):
        try:
            return get_ip_address(req[0]).is_loopback
        except Exception:
            pass

    def handle(self):
        self.remote = None
        try:
            self.encryptor = encrypt.Encryptor(self.server.key, self.server.method, servermode=True)
            sock = self.connection
            # sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            iv_len = self.encryptor.iv_len()
            if iv_len:
                try:
                    self.decrypt(self.rfile.read(iv_len))
                except ValueError:
                    logging.warn('server %s:%d iv reused, possible replay attrack. closing...' % self.server.server_address)
                    return
            data = sock.recv(1)
            if not data:
                return
            addrtype = ord(self.decrypt(data))
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(self.rfile.read(ord(self.decrypt(self.rfile.read(1)))))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6, self.decrypt(self.rfile.read(16)))
            else:  # not supported
                logging.warn('server %s:%d addr_type not supported, maybe wrong password' % self.server.server_address)
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))[0]
            if self.server.aports and port not in self.server.aports:
                logging.info('server %s:%d port %d not allowed' % (self.server.server_address[0], self.server.server_address[1], port))
                return
            if self._request_is_loopback((addr, port)):
                logging.info('server %s:%d localhost access denied' % self.server.server_address)
                return

            try:
                logging.info('server %s:%d request %s:%d from %s:%d' % (self.server.server_address[0], self.server.server_address[1],
                             addr, port, self.client_address[0], self.client_address[1]))
                data = self.decrypt(sock.recv(self.bufsize))

                if self.server.reverse:
                    if data.startswith((b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'TRACE', b'OPTIONS', b'PATCH', b'CONNECT')) and b'HTTP/1' in data and b'\r\n' in data:
                        data = data.decode('latin1')
                        data = data.replace('\r\n', '\r\nss-realip: %s:%s\r\nss-client: %s\r\n' % (self.client_address[0], self.client_address[1], self.server.key), 1)
                        self.remote = create_connection(self.server.reverse, timeout=10)
                    else:
                        a = 'CONNECT %s:%d HTTP/1.0\r\nss-realip: %s:%s\r\nss-client: %s\r\n\r\n' % (addr, port, self.client_address[0], self.client_address[1], self.server.key)
                        self.remote = create_connection(self.server.reverse, timeout=10)
                        self.remote.sendall(a.encode('latin1'))
                        remoterfile = self.remote.makefile('rb', 0)
                        d = remoterfile.readline()
                        while d not in (b'\r\n', b'\n', b'\r'):
                            if not d:
                                raise IOError(0, 'remote closed')
                            d = remoterfile.readline()
                if not self.remote:
                    self.remote = create_connection((addr, port), timeout=10)
                self.remote.sendall(data)
                # self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (IOError, OSError) as e:  # Connection refused
                logging.warn('server %s:%d %r on connecting %s:%d' % (self.server.server_address[0], self.server.server_address[1], e, addr, port))
                return
            self.handle_tcp(sock, self.remote)
        except socket.error as e:
            logging.warn('server %s:%d %r' % (self.server.server_address[0], self.server.server_address[1], e))

    def finish(self):
        SocketServer.StreamRequestHandler.finish(self)
        if self.remote:
            self.remote.close()


def start_servers(config):
    for serverinfo in config:
        try:
            logging.info('starting server: %s' % serverinfo)
            ssserver = ShadowsocksServer(serverinfo, Socks5Server)
            threading.Thread(target=ssserver.serve_forever).start()
        except Exception as e:
            logging.error('something wrong with config: %r' % e)


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    hello = 'shadowsocks-server %s' % __version__
    if gevent:
        hello += ' with gevent %s' % gevent.__version__
    print(hello)
    print('by v3aqb')

    config_path = None
    server = None

    if os.path.exists(os.path.join(os.path.dirname(__file__), 'config.json')):
        config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'c:f:')
        for key, value in optlist:
            if key == '-f':
                config_path = value
            if key == '-c':
                server = value

        if server:
            config = [server]
        elif config_path:
            logging.info('loading config from %s' % config_path)
            with open(config_path, 'rb') as f:
                try:
                    config = json.load(f)
                except ValueError as e:
                    logging.error('found an error in config.json: %s', e.message)
                    sys.exit(1)
        else:
            config = ['ss://aes-256-cfb:barfoo!@127.0.0.1:8388', ]

    except getopt.GetoptError:
        sys.exit(2)

    start_servers(config)

if __name__ == '__main__':
    try:
        main()
    except socket.error as e:
        logging.error(e)
    except KeyboardInterrupt:
        sys.exit(0)
