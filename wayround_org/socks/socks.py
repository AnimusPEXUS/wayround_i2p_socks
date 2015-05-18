

"""
Based on RFC1928
"""

import logging
import socket
import struct

import wayround_org.socketserver.server


def _render_addr(atyp, bnd_addr):
    """
    atyp:
        0x01 or socket.AF_INET for IPv4
        0x04 or socket.AF_INET6 for IPv6
        0x03 or 'hostname' to use hostname as address
    """

    if atyp == socket.AF_INET:
        atyp = 0x01

    elif atype == socket.AF_INET6:
        atyp = 0x04

    elif atype == 'hostname':
        atyp = 0x03

    else:
        pass

    ret = b''
    addr = None

    if atyp == 0x01:
        ret += b'\x01'
        ret += socket.inet_pton(socket.AF_INET, bnd_addr)
    elif atyp == 0x04:
        ret += b'\x04'
        ret += socket.inet_pton(socket.AF_INET6, bnd_addr)
    elif atyp == 0x03:
        ret += b'\x03'
        bnd_addr_bytes = bytes(bnd_addr, 'utf-8')
        addr_len = len(bnd_addr_bytes)
        if addr_len > 255:
            raise ValueError("loo long name in bnd_addr")
        ret += bytes([addr_len])
        ret += bnd_addr_bytes
    else:
        raise Exception("invalid atyp")

    return ret


def render_request(cmd, atyp, bnd_addr, bnd_port):
    """
    """ + _render_addr.__doc__

    if isinstance(cmd, str):

        cmd_l = cmd.lower()

        if cmd_l

        if cmd_l == 'connect':
            cmd = 0x01

        elif cmd_l == 'bind':
            cmd = 0x02

        elif cmd_l == 'associate':
            cmd = 0x03

        else:
            raise ValueError("cmd invalid keyword")

    if not isinstance(cmd, int):
        raise ValueError("cmd value error")

    if not cmd in range(1, 4):
        raise ValueError("invalid cmd value")

    ret = b'0x05'
    ret += bytes([cmd])
    ret += b'\x00'
    ret += _render_addr(atyp, bnd_addr)
    ret += struct.pack('>H', bnd_port)

    return ret


def render_reply(rep, atyp, bnd_addr, bnd_port):
    """
    """ + _render_addr.__doc__

    if not rep in range(10):
        raise ValueError("invalid rep value")

    ret = b'0x05'
    ret += bytes([rep])
    ret += b'\x00'
    ret += _render_addr(atyp, bnd_addr)
    ret += struct.pack('>H', bnd_port)

    return ret


def _recv_addr(sock):
    addr = None
    if atyp == 0x01:
        addr = list(sock.recv(4))
        addr = socket.inet_ntop(socket.AF_INET, addr)
    elif atyp == 0x04:
        addr = list(sock.recv(16))
        addr = socket.inet_ntop(socket.AF_INET6, addr)
    elif atyp == 0x03:
        addr_len = ord(sock.recv(1))
        addr = sock.recv(addr_len)
        del addr_len
    else:
        raise Exception("invalid atyp")
    return addr


def read_request_or_reply(sock, _debug=False):

    ver = ord(sock.recv(1))
    if _debug:
        print("        ver: {}".format(ver))

    if ver != 5:
        raise Exception("Invalid SOCKS version proposed")

    cmd = ord(sock.recv(1))
    if _debug:
        print("        command(or reply in case or reply): {}".format(cmd))

    # reserved and not used farver
    rsv = sock.recv(1)

    atyp = ord(sock.recv(1))

    if _debug:
        print("        atyp: {}".format(atyp))

    addr = _recv_addr(sock)

    if _debug:
        print("        addr: {}".format(addr))

    port = struct.unpack('>H', sock.recv(2))[0]

    if _debug:
        print("        port: {}".format(port))

    return ver, cmd, rsv, atyp, addr, port


class Server:

    def __init__(self, sock, func):
        """
        SOCKS5 Server implementation

        Requirements to sock is same as by SocketServer: be bound and listening

        func must accept one parameter. func will be called on (successfull
        auth dialog + successfull request parse) including 0xff auth method
        selected (when server does not supports any of methods proposed by
        client)

        the parameter for func will have following structure:

            dict(
                socket_server_values=dict(
                    utc_datetime=utc_datetime,
                    serv=serv,
                    serv_stop_event=serv_stop_event,
                    sock=sock,
                    addr=addr
                    ),
                auth_values=dict(
                    ver=ver,
                    auth=auth,
                    auth_data=auth_data
                    ),
                request_values=dict(
                    ver=ver,
                    cmd=cmd,
                    rsv=rsv,
                    atyp=atyp,
                    addr=addr,
                    port=port
                    )
                )

        the values in 'socket_server_values' are equal to sockt server
        callback's. 'auth_values' are not implemented at the moment and may
        disapear in the future. values in 'request_values' are parsing result
        as stated in RFC


        """

        ss = wayround_org.socketserver.server.SocketServer(
            s,
            self._on_accept
            )

        self.socket_server = ss

        self.start = ss.start
        self.stop = ss.stop
        self.wait = ss.wait

        self._func = func

        return

    def _on_accept(self, utc_datetime, serv, serv_stop_event, sock, addr):

        _debug = False

        if _debug:

            logging.debug("""\
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

            if _debug:
                logging.debug("Client proposed methods")

            for i in list(methods):
                if _debug:
                    logging.debug("    {}".format(i))

            if _debug:
                print("    LIST END")

            auth = None
            auth_data = None
            request = None
            if 0 in methods:
                if _debug:
                    logging.debug("sending x05x00")
                auth = 0
                sock.send(b'\x05\x00')
                request = read_request_or_reply(sock, _debug=_debug)

            else:
                auth = 0xff
                sock.send(b'\x05\xFF')

            result = dict(
                socket_server_values=dict(
                    utc_datetime=utc_datetime,
                    serv=serv,
                    serv_stop_event=serv_stop_event,
                    sock=sock,
                    addr=addr
                    ),
                auth_values=dict(
                    ver=ver,
                    auth=auth,
                    auth_data=auth_data
                    ),
                request_values=None
                )

            if request is not None:
                result['request_values'] = dict(
                    ver=request[0],
                    cmd=request[1],
                    rsv=request[2],
                    atyp=request[3],
                    addr=request[4],
                    port=request[5]
                    )

            self._func(result)

        except:
            logging.exception("error")
        finally:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    return


class Client:

    def __init__(self, addr, sock):
        self._addr = addr
        self.sock = sock
        return

    def action(self, cmd, atyp, bnd_addr, bnd_port):

        ret = None

        req = render_request(cmd, atyp, bnd_addr, bnd_port)

        self.sock.connect(self._addr)

        self.sock.send(req)

        try:
            reply = read_request_or_reply(self.sock)
            if cmd == 2:
                # recieving second reply
                reply = (
                    reply,
                    read_request_or_reply(self.sock)
                    )
        except:
            logging.exception("Error recieving SOCKS server reply")
        else:
            ret = reply

        return ret

    def connect(self, atyp, bnd_addr, bnd_port):
        return self.action(1, atyp, bnd_addr, bnd_port)

    def bind(self, atyp, bnd_addr, bnd_port):
        """
        Returns 2-tuple with two responses (read RFC)
        """
        return self.action(2, atyp, bnd_addr, bnd_port)

    def associate(self, atyp, bnd_addr, bnd_port):
        return self.action(3, atyp, bnd_addr, bnd_port)
