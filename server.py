# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import contextlib
import enum
import errno
import functools
import socket
import socketserver
import struct
import threading
import traceback
import logging

import dns.message
import dns.rcode
import dns.version

from dns import rdataclass, rdatatype

logger = logging.getLogger(__file__)

class Protocol(enum.IntEnum):
    UDP = 1
    TCP = 2

class Request:
    def __init__(self, message, wire, address, port, protocol):
        self.message = message
        self.wire = wire
        self.address = address
        self.port = port
        self.protocol = protocol

    @property
    def opcode(self):
        return self.message.opcode()

    @property
    def question(self):
        return self.message.question[0]

    @property
    def qname(self):
        return self.question.name

    @property
    def qclass(self):
        return self.question.rdclass

    @property
    def qtype(self):
        return self.question.rdtype

    @property
    def keyname(self):
        return self.message.keyname

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def __init__(self, protocol):
        self._protocol = protocol

    @property
    def protocol(self):
        return self._protocol

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.debug("Handling %s data from %s.." % (self.__class__.__name__[:3], self.client_address))

        items = self.server.handler._handle(
            self.get_data(),
            self.client_address[0],
            self.client_address[1],
            self.protocol
        )

        for data in items:
            self.send_data(data)

        logger.debug("Done handling %s data from %s." % (self.__class__.__name__[:3], self.client_address))

class TCPRequestHandler(BaseRequestHandler):

    def __init__(self, request, client_address, server):
        BaseRequestHandler.__init__(self, Protocol.TCP)
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def get_data(self):
        data = self.request.recv(16384)
        sz = struct.unpack('!H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('!H', len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):

    def __init__(self, request, client_address, server):
        BaseRequestHandler.__init__(self, Protocol.UDP)
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

class Server(object):

    """Simple DNS Server thread, based on dnspython's nanoserver,
    but using socketserver instead of trio.

    Applications should subclass the server and override the handle()
    method to determine how the server responds to queries.  The
    default behavior is to refuse everything.
    """

    def __init__(self, address='127.0.0.1', port=53, enable_udp=True,
                 enable_tcp=True, origin=None, keyring=None):

        self.address = address
        self.port = port
        self.enable_udp = enable_udp
        self.enable_tcp = enable_tcp
        self.origin = origin
        self.keyring = keyring
        self.servers = []

    def _maybe_listify(self, thing):
        if isinstance(thing, list):
            return thing
        else:
            return [thing]

    def handle_query_in_soa(self, query, response):
        pass

    def handle_query(self, query, response):
        if query.qclass == rdataclass.IN and query.qtype == rdatatype.SOA:
            self.handle_query_in_soa(query, response)
        else:
            logger.warning("Refusing unsupported query.");
            response.set_rcode(dns.rcode.REFUSED)

    def handle_update(self, update, response):
        pass

    def handle(self, request):
        #
        # Handle message 'message'.  Override this method to change
        # how the server behaves.
        #
        # The return value is either a dns.message.Message, a bytes,
        # None, or a list of one of those.  We allow a bytes to be
        # returned for cases where handle wants to return an invalid
        # DNS message for testing purposes.  We allow None to be
        # returned to indicate there is no response.  If a list is
        # returned, then the output code will run for each returned
        # item.
        #
        logger.debug("Received: %s" % request)

        msg = request.message
        reply = dns.message.make_response(msg)
        reply.set_rcode(dns.rcode.REFUSED)

        if request.opcode == dns.opcode.QUERY:
            if (len(msg.question) == 0):
                logger.warning("Refusing request with no questions?!")
                return

            self.handle_query(request, reply)
        elif request.opcode == dns.opcode.UPDATE:
            self.handle_update(request, reply)
        else:
            logger.error("Unsupported query with opcode: %s" % request.opcode)

        logger.debug("Replying: %s" % reply)

        return reply

    def _handle(self, wire, address, port, protocol):
        #
        # This is the common code to parse wire format, call handle() on
        # the message, and then generate response wire format (if handle()
        # didn't do it).
        #
        # It also handles any exceptions from handle()
        #
        # Returns a (possibly empty) list of wire format message to send.
        #
        # XXXRTH It might be nice to have a "debug mode" in the server
        # where we'd print something in all the places we're eating
        # exceptions.  That way bugs in handle() would be easier to
        # find.
        #
        items = []
        q = r = None
        try:
            logger.debug("Decoding message from wire..")
            q = dns.message.from_wire(wire, keyring=self.keyring)
            logger.debug(" ==> %s" % q)
        except dns.message.ShortHeader:
            # There is no hope of answering this one!
            logger.error("Ignoring message with header too sort?!")
            return
        except dns.message.UnknownTSIGKey:
            # There is no hope of answering this one!
            logger.error("Refusing message from %s with unknown signature?!" % address)
        except Exception as e:
            logger.error("Unable to decode message: %s" % e, exc_info=True)

        if q is None:
            # Try to make a FORMERR using just the question section.
            try:
                q = dns.message.from_wire(wire, question_only=True)
                r = dns.message.make_response(q)
                r.set_rcode(dns.rcode.FORMERR)
                items.append(r)
            except Exception:
                # We could try to make a response from only the header
                # if dnspython had a header_only option to
                # from_wire(), or if we truncated wire outselves, but
                # for now we just drop.
                return

        try:
            # items might have been appended to above, so skip
            # handle() if we already have a response.
            if not items:
                request = Request(q, wire, address, port, protocol)
                items = self._maybe_listify(self.handle(request))
        except Exception as e:
            logger.error("Exception while handling network packet: %s" % e, exc_info=True)
            # Exceptions from handle get a SERVFAIL response.
            r = dns.message.make_response(q)
            r.set_rcode(dns.rcode.SERVFAIL)
            items = [r]

        tsig_ctx = None
        multi = len(items) > 1

        if multi and dns.version.MAJOR < 2:
            raise Exception("Multi-message TSIG support requires dnspython >= 2.0")

        for thing in items:
            if isinstance(thing, dns.message.Message) and dns.version.MAJOR >= 2:
                out = thing.to_wire(self.origin, multi=multi, tsig_ctx=tsig_ctx)
                tsig_ctx = thing.tsig_ctx
                yield out
            elif isinstance(thing, dns.message.Message):
                out = thing.to_wire(self.origin)
                yield out
            else:
                yield thing

    def start(self):
        logger.info("Starting server..")

        self.servers = []

        if self.enable_tcp:
            socketserver.TCPServer.allow_reuse_address = True
            self.servers.append(socketserver.ThreadingTCPServer((self.address, self.port), TCPRequestHandler))
        if self.enable_udp:
            self.servers.append(socketserver.ThreadingUDPServer((self.address, self.port), UDPRequestHandler))

        for s in self.servers:
            s.handler = self
            s.allow_reuse_address = True
            thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
            thread.daemon = True  # exit the server thread when the main thread terminates
            thread.start()
            logger.info("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    def stop(self):
        logger.info("Stopping server..")

        for s in self.servers:
            s.shutdown()

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
