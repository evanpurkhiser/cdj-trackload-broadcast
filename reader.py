#!/usr/bin/env python

import scapy.sendrecv
import scapy.packet
import scapy.all

import collections

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
            '\x12\x14\x0f\x04', # Track load request
            '\x30\x00\x0f\x06', # Track name request
            '\x21\x02\x0f\x02', # (?) Unsure
            '\x30\x00\x0f\x06', # Track data request (filename!)
        ]

    def transition_packet(self, packet_pair):
        # Check if this command matches the expected transition
        if packet_pair.first[0].command != self.command_states[self.state]:
            self.state = 0

            return

        self.state += 1

        # Did we just transition into the last state?
        if self.state == len(self.command_states):
            self.state = 0

            return True


data_parser   = CDJDataParser()
state_machine = TrackLoadStateMachine()

def handlePacketData(data, packet):
    """Extract track information on track load
    """
    packet_pair = data_parser.pair_packet(data)

    if packet_pair is None:
        return

    debug_packet_pair(packet_pair)

    if not state_machine.transition_packet(packet_pair):
        return

    if packet_pair.first[0].data[17:26] != '\x01\x08\x04\x01\x11\x00\x00\x00\x00':
        return

    text = packet_pair.second[5].data[36:].split('\x00\x00\x11')[0]
    text = text.decode('utf-16-be').encode('utf-8')

    print(text)
    print('')

    return


def handlePacket(packet):
    """Extract the packet load and pass it into the packet state machine.
    """
    payload = packet['TCP'].payload

    # Do not deal with padding packets
    if isinstance(payload, scapy.packet.Padding):
        return

    # Ensure the packet contains raw data
    if not isinstance(payload, scapy.packet.Raw):
        return

    handlePacketData(payload.load, packet)


# Start sniffing CDJ <-> Rekordbox packets
scapy.sendrecv.sniff(filter='tcp', prn=handlePacket)
