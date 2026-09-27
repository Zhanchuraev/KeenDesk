"""Wire protocol test against a disposable CI server, not a RustDesk GUI test."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import socket
import sys
import time
import uuid


def var(n):
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    return bytes(result + bytes([n]))


def field(n, value):
    if isinstance(value, str): value = value.encode()
    return var((n << 3) | 2) + var(len(value)) + value


def fields(data):
    position, result = 0, {}
    def read():
        nonlocal position
        n = shift = 0
        while True:
            byte = data[position]; position += 1
            n |= (byte & 127) << shift
            if byte < 128: return n
            shift += 7
    while position < len(data):
        tag = read()
        if tag & 7 == 0: value = read()
        elif tag & 7 == 2:
            length = read()
            value = data[position:position+length]; position += length
        else: raise ValueError('Unsupported protobuf wire type')
        result[tag >> 3] = value
    return result


def frame(data):
    size = next(n for n in range(1,5) if len(data) < 1 << (n*8-2))
    return ((len(data) << 2) | (size-1)).to_bytes(size,'little') + data


def exact(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(min(65536,length-len(result)))
        if not chunk: raise EOFError('Connection closed')
        result.extend(chunk)
    return bytes(result)


def receive(sock):
    first = exact(sock,1)
    header = first + exact(sock,first[0] & 3)
    return exact(sock,int.from_bytes(header,'little') >> 2)


def main():
    host, key_file = sys.argv[1:]
    key = Path(key_file).read_text().strip()
    def tcp(port): return socket.create_connection((host,port),timeout=8)
    for port in (21115,21116):
        with tcp(port) as sock:
            sock.sendall(frame(field(20,b'')))
            assert fields(fields(receive(sock))[21])[1] == sock.getsockname()[1]
    print('PASS native TCP NAT on 21115 and 21116',flush=True)
    peer = 'ci'+uuid.uuid4().hex
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(3); udp.connect((host,21116))
        def exchange(message,tag):
            for attempt in range(4):
                udp.send(message)
                try: return fields(fields(udp.recv(4096))[tag])
                except socket.timeout:
                    if attempt == 3: raise
        assert exchange(field(6,field(1,peer)),7).get(2) == 1
        assert exchange(field(15,field(1,peer)+field(2,uuid.uuid4().bytes)+field(3,os.urandom(32))),16).get(1,0) == 0
        assert exchange(field(6,field(1,peer)),7).get(2,0) == 0
        with tcp(21116) as sock:
            sock.sendall(frame(field(8,field(1,peer)+var(2 << 3)+var(2)+field(3,key)+field(6,'1.4.9'))))
            reply = fields(udp.recv(4096))
            assert fields(reply.get(12,reply.get(9,b'')))[2].decode() == host+':21117'
        with tcp(21116) as sock:
            sock.sendall(frame(field(8,field(1,peer)+field(3,'invalid-ci-key'))))
            assert fields(fields(receive(sock))[11])[3] == 3
    print('PASS UDP registration, presence, advertised relay and wrong-key rejection',flush=True)
    for _ in range(2):
        request = frame(field(18,field(1,'ci-relay')+field(2,str(uuid.uuid4()))+field(6,key)))
        with tcp(21117) as a, tcp(21117) as b:
            a.sendall(request); time.sleep(.15)
            b.sendall(request); time.sleep(.15)
            for sender,receiver in ((a,b),(b,a)):
                payload = os.urandom(256*1024)
                with concurrent.futures.ThreadPoolExecutor(1) as pool:
                    pending = pool.submit(exact,receiver,len(payload))
                    sender.sendall(payload)
                    result = pending.result(timeout=20)
                assert hashlib.sha256(result).digest() == hashlib.sha256(payload).digest()
    print('PASS relay two sessions, 1 MiB total, both directions, SHA-256',flush=True)
    for port in (21118,21119):
        with socket.socket() as sock:
            sock.settimeout(.5)
            assert sock.connect_ex((host,port)) != 0
    print('PASS WebSocket ports blocked from client namespace',flush=True)


if __name__ == '__main__': main()
