import socket
import struct
from general import *


class Ethernet:

    def __init__(self, raw_data):

        destination_address, source_address, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = get_mac_addr(destination_address)
        self.src_mac = get_mac_addr(source_address)
        self.proto = socket.htons(prototype)
        self.data = raw_data[14:]



