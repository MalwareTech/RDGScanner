from OpenSSL import SSL
from OpenSSL._util import (lib as _lib)
import sys
import socket
import struct
import threading

# PyOpenSSL doesn't expose the DTLS method to python, so we have to patch it
DTLSv1_METHOD = 7
SSL.Context._methods[DTLSv1_METHOD] = getattr(_lib, "DTLSv1_client_method")

vulnerable = True
connected = False


def build_connect_packet(fragment_id, num_fragments, data):
    packet_type = 5
    packet_len = len(data) + 6
    fragment_id = fragment_id
    num_fragments = num_fragments
    fragment_len = len(data)
    data = data

    packet = struct.pack('<HHHHH', packet_type, packet_len, fragment_id,
                         num_fragments, fragment_len)
    packet += data
    return packet


def certificate_callback(sock, cert, err_num, depth, ok):
    global connected

    server_name = cert.get_subject().commonName
    print('Got certificate for server: %s' % server_name)

    connected = True
    return True


def scan_server(ip, port):
    global vulnerable

    print('Checking to {}:{}'.format(ip, port))

    ctx = SSL.Context(DTLSv1_METHOD)
    ctx.set_verify_depth(2)
    ctx.set_verify(SSL.VERIFY_PEER, certificate_callback)

    sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

    sock.connect((ip, int(port)))
    sock.send(build_connect_packet(0, 65, b"A"))

    data = sock.recv(1024)
    if len(data) == 16:
        error_code = struct.unpack('<L', data[12:])[0]
        if error_code == 0x8000ffff:
            vulnerable = False


if __name__ == '__main__':
    # if server doesn't respond before timeout, we assume it's patched
    # setting the timeout too low can result in false
    timeout_secs = 3

    # PyOpenSSL doesn't support settimeout(), so we have to implement our own pseudo-timeout
    thread = threading.Thread(target=scan_server, args=(sys.argv[1], sys.argv[2]))
    thread.start()
    thread.join(timeout_secs)

    if connected:
        if vulnerable:
            print('Scan Completed: server is vulnerable')
        else:
            print('Scan Completed: server is not vulnerable')
    else:
        print('ERROR: could not connect to server')



