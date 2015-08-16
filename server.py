#!/usr/bin/env python

import scapy.sendrecv
import scapy.packet
import scapy.all
import collections
import asyncore
import socket
import threading
import optparse

def hex2str(data): return ":".join("{:02x}".format(ord(c)) for c in data)

def debug_packet_pair(packet_pair):
    print("Packet identifier: {}".format(hex2str(packet_pair.identifier)))
    print('>>>')
    print('\n'.join(hex2str(p.command) + ' - ' +  hex2str(p.data) for p in packet_pair.first))
    print('<<<')
    print('\n'.join(hex2str(p.command) + ' - ' +  hex2str(p.data) for p in packet_pair.second))
    print('---')
    print('')


# When the CDJs / Rekordbox talk to each other a packet is sent and the
# opposite end will send a response. each packet includes an identifier
# indicating which previous packet it is a response for. We can group these
# together into a single object called a 'PacketPair'.
#
# PacketPairs `first` and `second` attributes are lists of PacketParts.
PacketPair = collections.namedtuple('PacketPair', ['identifier', 'first', 'second'])

# Each packet communicated to and from the CDJ contains multiple parts. Each
# part is constructed of the packet identifier, a 'command' issued by the part,
# and some data.
PacketPart = collections.namedtuple('PacketPart', ['identifier', 'command', 'data'])

# This header starts each "section" of a packet
CDJ_SECTION_MARKER = '\x11\x87\x23\x49\xae\x11'

class CDJDataParser(object):
    """Reads packets from the CDJs and pairs them two at a time.
    """
    @staticmethod
    def parse_data(data):
        """Parse a CDJ packet into parts with the identifier, command, and data

        This assumes that all packets will start with the `CDJ_SECTION_MARKER`,
        otherwise the packet is not in communcation with the CDJ. Packets with
        no parts will be ignored.
        """
        if data[:6] != CDJ_SECTION_MARKER:
            return

        # Split the packet into sections, Ignore the first empty element
        packet_items = data.split(CDJ_SECTION_MARKER)[1:]

        # Ignore empty data
        if not packet_items:
            return

        # CDJ packets are made of 3 sections (as far as I can tell).
        #
        # 1. The first four bytes are the 'identifier' for the associated
        #    response packet.
        #
        # 2. The next byte appears to be some kinda of separator, followed by
        #    four more bytes which seems to be the 'command' for the packet.
        #
        # The rest of the packet is data.
        return [PacketPart(p[:4], p[5:9], p[10:]) for p in packet_items]

    def __init__(self):
        self.initial_packets = {}

    def pair_packet(self, data):
        """Pair a TCP packet with the associated CDJ packet it belongs to

        When a packet is paried to a previous packet with the same identifier
        this method will return the PacketPair, returns None otherwise.
        """
        parts = CDJDataParser.parse_data(data)

        if parts is None:
            return

        # For almost all of the packets, as far as I can tell, each part will
        # have the same identifier. I have seen some cases (specifically when
        # scrolling through the key list) where the packet identifier differs,
        # but hopefyull that doesn't cause any problems.
        #
        # For now use the identifier of the first part
        identifier = parts[0].identifier

        if identifier not in self.initial_packets:
            self.initial_packets[identifier] = parts
        else:
            first_parts = self.initial_packets.pop(identifier)

            return PacketPair(identifier, first_parts, parts)

        # Explicity return nothing if we haven't paired a packet yet
        return None


class TrackLoadStateMachine(object):
    """State machine to keep track of a track load sequence.
    """
    def __init__(self):
        self.state = 0
        self.command_states = [
            lambda p: p[0].data[18:21] == '\x03\x04\x01',
            '\x30\x00\x0f\x06',       # Begin track loading
            '\x21\x02\x0f\x02',       # (?) Unsure
            '\x30\x00\x0f\x06',       # Track data request (filename!)
        ]

    def transition_packet(self, packet_pair):
        """Transition the machine via a packet
        """
        state_transition = self.command_states[self.state]

        state_operation = state_transition

        # If the state operation is a string assume that we want to verify that
        # the command of the first part matches the configured state transition
        if not hasattr(state_operation, '__call__'):
            state_operation = lambda x: x[0].command == state_transition

        # Check if this packet fufills the state operation
        if not state_operation(packet_pair.first):
            self.state = 0
            return

        # Success, transition to the next state
        self.state += 1

        # Did we just transition into the last state?
        if self.state == len(self.command_states):
            self.state = 0
            return True


def get_track_load_details(packet_pair):
    """Extracts track load details from a track-load packet

    The return of this method will include the CDJ identifier and the path of
    the track that was loaded by this packet pair.
    """
    cdj_id = ord(packet_pair.first[0].data[17])

    path = packet_pair.second[5].data[36:].split('\x00\x00\x11')[0]
    path = path.decode('utf-16-be').encode('utf-8')

    return (cdj_id, path)


if __name__ == '__main__':
    data_parser   = CDJDataParser()
    state_machine = TrackLoadStateMachine()

    parser = optparse.OptionParser()
    parser.add_option('-a', '--addr', dest='addr', default='0.0.0.0')
    parser.add_option('-p', '--port', dest='port', default=19000)
    parser.add_option('-b', '--base-path', dest='base_path')

    opts, args = parser.parse_args()

    class Server(asyncore.dispatcher):
        def __init__(self, host, port):
            asyncore.dispatcher.__init__(self)
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind((host, port))
            self.listen(1)

        def handle_accept(self):
            pair = self.accept()
            if pair is None:
                return

            sock, addr = pair
            print('Incoming connection from {}'.format(repr(addr)))
            self.connection = sock

        def handle_close(self):
            if self.connection: self.connection.close()

        def send(self, message):
            if self.connection: self.connection.send(message)

    server = Server(opts.addr, opts.port)

    socket_loop = threading.Thread(target=asyncore.loop, name="Asyncore Loop")
    socket_loop.start()

    def handle_packet(packet):
        """Extract the packet load and pass it into the packet state machine.
        """
        payload = packet['TCP'].payload

        # Do not deal with padding packets
        if isinstance(payload, scapy.packet.Padding):
            return

        # Ensure the packet contains raw data
        if not isinstance(payload, scapy.packet.Raw):
            return

        # Pair up CDJ packets
        packet_pair = data_parser.pair_packet(payload.load)

        if packet_pair is None:
            return

        # Look for track-load transition sequences
        if not state_machine.transition_packet(packet_pair):
            return

        cdj_id, path = get_track_load_details(packet_pair)

        # Remove the base path from the 
        if opts.base_path and path.startswith(opts.base_path):
            path = path[len(opts.base_path):]

        server.send('{:02d}:{}\n'.format(cdj_id, path))


    # Start sniffing CDJ <-> Rekordbox packets
    scapy.sendrecv.sniff(filter='tcp', prn=handle_packet)
    asyncore.close_all()
