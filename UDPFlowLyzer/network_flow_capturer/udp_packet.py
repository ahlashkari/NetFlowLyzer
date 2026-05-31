#!/usr/bin/env python3

import socket
import datetime
from datetime import datetime


class UDPPacket():
    def __init__(self, src_ip="", src_port=0, dst_ip="", dst_port=0, protocol=None,
            timestamp=0, forward=True, length=0, payloadbytes=0, header_size=0):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.timestamp = timestamp
        self.forward = forward
        self.length = length
        self.payloadbytes = payloadbytes
        self.header_size = header_size
        self.__segment_size = self.header_size + self.payloadbytes

    def __len__(self):
        return self.get_length
    
    def __lt__(self, o: object):
        return (self.timestamp <= o.get_timestamp())

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port
    
    def get_protocol(self):
        return self.protocol
    
    def get_timestamp(self):
        return self.timestamp

    def get_length(self):
        return self.length

    def get_payloadbytes(self):
        return self.payloadbytes

    def get_header_size(self):
        return self.header_size

    def get_segment_size(self):
        return self.__segment_size

    def get_payload_bytes(self):
        return self.payloadbytes

    def is_forward(self):
        """Return whether this packet is in the forward direction."""
        return self.forward

    def __str__(self):
        return "_".join([str(self.src_ip), str(self.src_port), str(self.dst_ip), str(self.dst_port),
                         str(self.protocol), str(datetime.fromtimestamp(float(self.timestamp)))]) 