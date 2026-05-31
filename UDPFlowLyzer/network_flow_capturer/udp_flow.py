#!/usr/bin/env python3

import datetime
from datetime import datetime
from typing import List
from .udp_packet import UDPPacket


class UDPFlow(object):    
    def __init__(self, packet, activity_timeout):
        self.src_ip = packet.get_src_ip()
        self.dst_ip = packet.get_dst_ip()
        self.src_port = packet.get_src_port()
        self.dst_port = packet.get_dst_port()
        self.protocol = packet.get_protocol()
        self.__activity_timeout = activity_timeout
        self.flow_start_time = float(packet.get_timestamp())
        self.flow_last_seen = float(packet.get_timestamp())
        self.packets = []
        self.sflastts = -1
        self.sfcount = 0
        self.flow_active = []
        self.flow_idle = []
        self.start_active_time = float(packet.get_timestamp())
        self.end_active_time = float(packet.get_timestamp())

        # UDP-specific bulk features
        self.fbulkDuration = 0
        self.fbulkPacketCount = 0
        self.fbulkSizeTotal = 0
        self.fbulkStateCount = 0
        self.fbulkPacketCountHelper = 0
        self.fbulkStartHelper = 0
        self.fbulkSizeHelper = 0
        self.flastBulkTS = 0
        self.bbulkDuration = 0
        self.bbulkPacketCount = 0
        self.bbulkSizeTotal = 0
        self.bbulkStateCount = 0
        self.bbulkPacketCountHelper = 0
        self.bbulkStartHelper = 0
        self.bbulkSizeHelper = 0
        self.blastBulkTS = 0

    def __str__(self):
        return "_".join([str(self.src_ip), str(self.src_port), str(self.dst_ip), str(self.dst_port),
                         str(self.protocol), str(datetime.fromtimestamp(float(self.flow_start_time)))])

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

    def get_flow_start_time(self):
        return self.flow_start_time

    def get_flow_last_seen(self):
        return self.flow_last_seen

    def get_timestamp(self):
        return self.flow_start_time

    def get_packets(self):
        return self.packets

    def add_packet(self, packet):
        if packet.forward:
            self.__forward_bulk_update(packet)
        else:
            self.__backward_bulk_update(packet)

        self.packets.append(packet)
        self.update_active_idle_time(packet)

    def update_active_idle_time(self, packet):
        if (float(packet.get_timestamp()) - float(self.flow_last_seen)) > 1.0:
            if self.start_active_time != 0:
                self.flow_idle.append(1000000 * (self.start_active_time - self.end_active_time))
            self.start_active_time = float(packet.get_timestamp())
            self.end_active_time = float(packet.get_timestamp())
        else:
            self.end_active_time = float(packet.get_timestamp())

        if (float(packet.get_timestamp()) - float(self.flow_last_seen)) > self.__activity_timeout:
            if self.start_active_time != 0:
                self.flow_active.append(1000000 * (self.end_active_time - self.start_active_time))
        self.flow_last_seen = float(packet.get_timestamp())

    def activity_timeout(self, packet):
        active_time = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(self.flow_last_seen))
        return active_time.total_seconds() > self.__activity_timeout

    def get_fwd_packets(self):
        return [pkt for pkt in self.packets if pkt.forward]

    def get_bwd_packets(self):
        return [pkt for pkt in self.packets if not pkt.forward]

    def __forward_bulk_update(self, packet):
        if (float(packet.get_timestamp()) - self.flastBulkTS) > 1.0:
            self.fbulkStartHelper = float(packet.get_timestamp())
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = packet.get_payloadbytes()
            self.flastBulkTS = float(packet.get_timestamp())
        elif (float(packet.get_timestamp()) - self.flastBulkTS) < 1.0 and (float(packet.get_timestamp()) - self.flastBulkTS) > 0.0:
            self.fbulkPacketCountHelper += 1
            self.fbulkSizeHelper += packet.get_payloadbytes()
            if self.fbulkPacketCountHelper == 4:
                self.fbulkStateCount += 1
                self.fbulkPacketCount += self.fbulkPacketCountHelper
                self.fbulkSizeTotal += self.fbulkSizeHelper
                self.fbulkDuration += float(packet.get_timestamp()) - self.fbulkStartHelper
            elif self.fbulkPacketCountHelper > 4:
                self.fbulkPacketCount += 1
                self.fbulkSizeTotal += packet.get_payloadbytes()
                self.fbulkDuration += float(packet.get_timestamp()) - self.flastBulkTS
            self.flastBulkTS = float(packet.get_timestamp())

    def __backward_bulk_update(self, packet):
        if (float(packet.get_timestamp()) - self.blastBulkTS) > 1.0:
            self.bbulkStartHelper = float(packet.get_timestamp())
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = packet.get_payloadbytes()
            self.blastBulkTS = float(packet.get_timestamp())
        elif (float(packet.get_timestamp()) - self.blastBulkTS) < 1.0 and (float(packet.get_timestamp()) - self.blastBulkTS) > 0.0:
            self.bbulkPacketCountHelper += 1
            self.bbulkSizeHelper += packet.get_payloadbytes()
            if self.bbulkPacketCountHelper == 4:
                self.bbulkStateCount += 1
                self.bbulkPacketCount += self.bbulkPacketCountHelper
                self.bbulkSizeTotal += self.bbulkSizeHelper
                self.bbulkDuration += float(packet.get_timestamp()) - self.bbulkStartHelper
            elif self.bbulkPacketCountHelper > 4:
                self.bbulkPacketCount += 1
                self.bbulkSizeTotal += packet.get_payloadbytes()
                self.bbulkDuration += float(packet.get_timestamp()) - self.blastBulkTS
            self.blastBulkTS = float(packet.get_timestamp()) 