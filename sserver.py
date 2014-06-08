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


import socket
import select
import threading
import SocketServer
import struct
import logging
import getopt
import encrypt
import os
import urlparse


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

    def server_activate(self):
        self.socket.listen(self.request_queue_size)

    def get_request(self):
        connection = self.socket.accept()
        connection[0].settimeout(10)
        return connection


class Socks5Server(SocketServer.StreamRequestHandler):
    timeout = 10

    def handle_tcp(self, sock, remote, timeout=600):
        try:
            iw = [sock, remote]
            count = 0
            while True:
                try:
                    (ins, _, exs) = select.select(iw, [], iw, 1)
                    if exs:
                        break
                    if sock in ins:
                        data = self.decrypt(sock.recv(4096))
                        if data:
                            result = send_all(remote, data)
                            if result < len(data):
                                raise Exception('failed to send all data')
                            count = 0
                        elif count < timeout:
                            count = timeout  # make sure all data are read before we close the sockets
                    if remote in ins:
                        data = self.encrypt(remote.recv(4096))
                        if data:
                            result = send_all(sock, data)
                            if result < len(data):
                                raise Exception('failed to send all data')
                        elif count < timeout:
                            count = timeout
                    if count > timeout:
                        break
                    count += 1
                except socket.error as e:
                    logging.debug('socket error: %s' % e)
                    break
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def handle(self):
        self.remote = None
        try:
            self.encryptor = encrypt.Encryptor(self.server.key, self.server.method, servermode=True)
            sock = self.connection
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            iv_len = self.encryptor.iv_len()
            data = sock.recv(iv_len)
            if iv_len > 0 and not data:
                return
            if iv_len:
                try:
                    self.decrypt(data)
                except ValueError:
                    logging.warn('iv reused, possible replay attrack')
            data = sock.recv(1)
            if not data:
                return
            addrtype = ord(self.decrypt(data))
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6, self.decrypt(self.rfile.read(16)))
            else:
                # not supported
                logging.warn('addr_type not supported, maybe wrong password')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            try:
                logging.info('server %s:%d request %s:%d from %s:%d' % (self.server.server_address[0], self.server.server_address[1],
                             addr, port[0], self.client_address[0], self.client_address[1]))
                self.remote = socket.create_connection((addr, port[0]), timeout=10)
                self.remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except socket.error, e:  # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(sock, self.remote)
        except socket.error, e:
            logging.warn(e)

    def finish(self):
        SocketServer.StreamRequestHandler.finish(self)
        if self.remote:
            self.remote.close()


def main():
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    hello = 'shadowsocks-server %s' % __version__
    if gevent:
        hello += ' with gevent %s' % gevent.__version__
    print hello
    print 'by v3aqb'

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

    tcp_servers = []
    for item in config:
        p = urlparse.urlparse(item)
        sshost, ssport, ssmethod, sskey = (p.hostname, p.port, p.username, p.password)
        try:
            encrypt.check(sskey, ssmethod)
            addrs = socket.getaddrinfo(sshost, 8388)
            if not addrs:
                logging.error('cant resolve listen address')
            ThreadingTCPServer.address_family = addrs[0][0]
            tcp_server = ThreadingTCPServer((sshost, int(ssport)), Socks5Server)
            tcp_server.key, tcp_server.method = sskey, ssmethod
            logging.info('starting server: %s' % item)
            tcp_servers.append(tcp_server)
        except Exception as e:
            logging.error('something wrong with config: %r' % e)

    for tcp_server in tcp_servers:
        threading.Thread(target=tcp_server.serve_forever).start()

if __name__ == '__main__':
    try:
        main()
    except socket.error, e:
        logging.error(e)
    except KeyboardInterrupt:
        exit(0)
