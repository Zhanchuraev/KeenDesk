"""Bounded native protocol probes. Never registers a persistent test peer."""
import hashlib
import os
import socket
import time
import uuid


def var(n):
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    return bytes(out + bytes([n]))


def field(n, value):
    if isinstance(value, str): value = value.encode()
    return var((n << 3) | 2) + var(len(value)) + value


def fields(data):
    pos, result = 0, {}
    def read():
        nonlocal pos
        n = 0
        for shift in range(0, 70, 7):
            if pos >= len(data): raise ValueError('Truncated protobuf')
            byte = data[pos]; pos += 1
            n |= (byte & 127) << shift
            if byte < 128: return n
        raise ValueError('Oversized varint')
    while pos < len(data):
        tag = read()
        if tag & 7 == 0: value = read()
        elif tag & 7 == 2:
            length = read()
            if pos + length > len(data): raise ValueError('Truncated protobuf field')
            value = data[pos:pos+length]; pos += length
        else: raise ValueError('Unsupported protobuf wire type')
        result[tag >> 3] = value
    return result


def frame(data):
    size = next(n for n in range(1,5) if len(data) < 1 << (n*8-2))
    return ((len(data) << 2) | (size-1)).to_bytes(size,'little') + data


def exact(sock, length):
    if not 0 <= length <= 1024*1024: raise ValueError('Oversized response')
    out = bytearray()
    while len(out) < length:
        chunk = sock.recv(length-len(out))
        if not chunk: raise EOFError('Connection closed')
        out.extend(chunk)
    return bytes(out)


def receive(sock):
    first = exact(sock,1)
    header = first + exact(sock,first[0] & 3)
    return exact(sock,int.from_bytes(header,'little') >> 2)


def id_probe(host='127.0.0.1'):
    with socket.create_connection((host,21116),timeout=3) as sock:
        sock.sendall(frame(field(20,b'')))
        result = fields(fields(receive(sock)).get(21,b''))
        if not result.get(1): raise RuntimeError('Нет TestNatResponse от ID-службы')
    return 'TCP 21116: получен TestNatResponse'


def udp_probe(host='127.0.0.1'):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(3); sock.connect((host,21116))
        sock.send(field(6,field(1,'doctor-'+uuid.uuid4().hex)))
        result = fields(sock.recv(4096))
        if 7 not in result: raise RuntimeError('Нет RegisterPeerResponse по UDP')
    return 'UDP 21116: ответ получен; запись в базе не создавалась'


def relay_probe(key,host='127.0.0.1'):
    request = frame(field(18,field(1,'keendesk-doctor')+field(2,str(uuid.uuid4()))+field(6,key)))
    with socket.create_connection((host,21117),timeout=3) as a, \
         socket.create_connection((host,21117),timeout=3) as b:
        a.sendall(request); time.sleep(.1)
        b.sendall(request); time.sleep(.1)
        for sender, receiver in ((a,b),(b,a)):
            data = os.urandom(4096)
            sender.sendall(data)
            if hashlib.sha256(exact(receiver,len(data))).digest() != hashlib.sha256(data).digest():
                raise RuntimeError('Relay: данные не совпали')
    return 'TCP 21117: 8 КиБ в обе стороны, SHA-256 совпал'


def required(key):
    id_probe(); udp_probe(); relay_probe(key)
