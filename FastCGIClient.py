#!/usr/bin/python

import socket
import random


class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            print(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        return bytes([FastCGIClient.__FCGI_VERSION,
                     fcgi_type,
                     (requestid >> 8) & 0xFF,
                     requestid & 0xFF,
                     (length >> 8) & 0xFF,
                     length & 0xFF,
                     0,
                     0]) + content

    def __encodeNameValueParams(self, name, value):
        name = name.encode('utf-8')
        value = value.encode('utf-8')
        nLen = len(name)
        vLen = len(value)
        record = bytearray()
        if nLen < 128:
            record.append(nLen)
        else:
            record.extend([
                (nLen >> 24) | 0x80,
                (nLen >> 16) & 0xFF,
                (nLen >> 8) & 0xFF,
                nLen & 0xFF])
        if vLen < 128:
            record.append(vLen)
        else:
            record.extend([
                (vLen >> 24) | 0x80,
                (vLen >> 16) & 0xFF,
                (vLen >> 8) & 0xFF,
                vLen & 0xFF])
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = stream[0]
        header['type'] = stream[1]
        header['requestId'] = (stream[2] << 8) + stream[3]
        header['contentLength'] = (stream[4] << 8) + stream[5]
        header['paddingLength'] = stream[6]
        header['reserved'] = stream[7]
        return header

    def __decodeFastCGIRecord(self):
        header = self.sock.recv(FastCGIClient.__FCGI_HEADER_SIZE)
        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = bytearray()
            if 'contentLength' in record.keys():
                contentLength = record['contentLength']
                buffer = self.sock.recv(contentLength)
                while contentLength and buffer:
                    contentLength -= len(buffer)
                    record['content'] += buffer
            if 'paddingLength' in record.keys():
                skiped = self.sock.recv(record['paddingLength'])
            return record

    def request(self, nameValuePairs=None, post=b''):
        if not self.__connect():
            print('connect failure! please check your fasctcgi-server !!')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = bytearray()
        beginFCGIRecordContent = bytes([
            0,
            FastCGIClient.__FCGI_ROLE_RESPONDER,
            self.keepalive,
            0, 0, 0, 0, 0])
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent,
                                              requestId)
        if nameValuePairs:
            paramsRecord = bytearray()
            for (name, value) in nameValuePairs.items():
                # paramsRecord = self.__encodeNameValueParams(name, value)
                # request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
                if isinstance(value, str):
                    paramsRecord += self.__encodeNameValueParams(name, value)
            if paramsRecord:
                request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)

        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN,
                                                  post.encode('utf=8'),
                                                  requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)
        self.sock.send(request)
        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND
        self.requests[requestId]['response'] = b''
        return self.__waitForResponse(requestId)

    def __waitForResponse(self, requestId):
        while True:
            response = self.__decodeFastCGIRecord()
            if not response:
                break
            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR
                if requestId == response['requestId']:
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)
