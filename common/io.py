# common/io.py
import socket

def send_line(sock: socket.socket, data: bytes):
    sock.sendall(data)

def recv_line(sock: socket.socket, bufsize: int = 65536) -> bytes:
    # lee hasta '\n'
    chunks = []
    while True:
        b = sock.recv(1)
        if not b:
            break
        chunks.append(b)
        if b == b'\n':
            break
    return b''.join(chunks)
