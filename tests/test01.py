
import logging
import socket
import struct

import wayround_org.socketserver.server


def ss_read_request_details(sock):

    ver = sock.recv(1)
    print("        ver: {}".format(ver))

    if ver != b'\x05':
        raise Exception("Invalid SOCKS version proposed")

    cmd = ord(sock.recv(1))
    print("        cmd: {}".format(cmd))

    # reserved and not used farver
    rsv = sock.recv(1)
    del (rsv)

    atyp = ord(sock.recv(1))

    print("        atyp: {}".format(atyp))

    addr = None
    if atyp == 0x01:
        addr = list(sock.recv(4))
    elif atyp == 0x04:
        addr = list(sock.recv(16))
    elif atyp == 0x03:
        addr_len = ord(sock.recv(1))
        addr = sock.recv(addr_len)
        del addr_len
    else:
        raise Exception("Invalid ATYP")

    print("        addr: {}".format(addr))

    port = struct.unpack('>H', sock.recv(2))[0]
    
    print("        port: {}".format(port))

    return


def ss_callable(utc_datetime, serv, serv_stop_event, sock, addr):

    print("""\
CONNECTION:
    {}
    {}
    {}
    {}
""".format(
        utc_datetime,
        serv,
        sock,
        addr
        )
        )

    try:
        ver = sock.recv(1)
        if ver != b'\x05':
            raise Exception("Invalid SOCKS version proposed")

        method_count = ord(sock.recv(1))

        if method_count not in range(1, 255):
            raise Exception("Invalid method count")

        methods = list(sock.recv(method_count))

        print("Client proposed methods")
        for i in list(methods):
            print("    {}".format(i))
        print("    LIST END")

        if 0 in methods:
            print("sending x05x00")
            sock.send(b'\x05\x00')
            ss_read_request_details(sock)
        else:
            sock.send(b'\x05\xFF')
        # for i in range(len(methods)):
    except:
        logging.exception("error")

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

    return


s = socket.socket()
s.bind(('127.0.0.1', 1080))
s.listen(0)

ss = wayround_org.socketserver.server.SocketServer(
    s,
    ss_callable
    )

ss.start()
try:
    ss.wait()
except KeyboardInterrupt:
    logging.exception("C-c")
    ss.stop()

s.shutdown(socket.SHUT_RDWR)
s.close()

exit(0)
