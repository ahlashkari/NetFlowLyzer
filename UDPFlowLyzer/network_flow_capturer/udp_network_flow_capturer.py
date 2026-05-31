#!/usr/bin/env python3

import datetime
from datetime import datetime
import dpkt
from dpkt import ethernet
import socket
import os
import time
from collections import defaultdict, Counter
from .udp_packet import UDPPacket
from .udp_flow import UDPFlow
class UDPNetworkFlowCapturer:
    def __init__(self, max_flow_duration: int, activity_timeout: int,
                check_flows_ending_min_flows: int, capturer_updating_flows_min_value: int,
                read_packets_count_value_log_info: int, vxlan_ip: str,
                continues_batch_address: str, continues_pcap_prefix: str,
                number_of_continues_files: int, continues_batch_mode: bool,
                base_number_continues_files:int):
        self.__finished_flows = []
        self.__ongoing_flows = {}
        self.__max_flow_duration = max_flow_duration
        self.__activity_timeout = activity_timeout
        self.__check_flows_ending_min_flows = check_flows_ending_min_flows
        self.__capturer_updating_flows_min_value = capturer_updating_flows_min_value
        self.__read_packets_count_value_log_info = read_packets_count_value_log_info
        self.__vxlan_ip = vxlan_ip
        self.__continues_batch_address = continues_batch_address
        self.__continues_pcap_prefix = continues_pcap_prefix
        self.__number_of_continues_files = number_of_continues_files
        self.__continues_batch_mode = continues_batch_mode
        self.__base_number_continues_files = base_number_continues_files
        self.flows_counter = 0
        self.udp_packets = 0
        self.ip_packets = 0
        self.all_packets = 0
    def pcap_parser(self, pcap_file: str, flows: list, flows_lock):
        print(f">> Analyzing UDP flows in {pcap_file}")
        self.packet_counter = 0
        self.udp_packet_counter = 0  # Counter specifically for UDP packets
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                self.packet_counter +=1  # Total packets seen
                try:
                    new_buf = buf
                    eth = dpkt.ethernet.Ethernet(buf)
                    while isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        if (
                            socket.inet_ntoa(ip.src) == self.__vxlan_ip
                            or socket.inet_ntoa(ip.dst) == self.__vxlan_ip
                        ):
                            raw = ip.data.data
                            if not isinstance(raw, (bytes, bytearray)):
                                raw = bytes(raw)
                            if len(raw) < 16 or len(raw[8:]) < 14:
                                break
                            try:
                                eth = dpkt.ethernet.Ethernet(raw[8:])
                                new_buf = raw[8:]
                                continue
                            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception):
                                break
                        break

                    if not isinstance(eth.data, dpkt.ip.IP) or not isinstance(eth.data.data, dpkt.udp.UDP):
                        continue
                    ip = eth.data
                
                    # Increment UDP packet counter only for actual UDP packets
                    self.udp_packet_counter += 1
                    udp_layer = ip.data
                    network_protocol = 'UDP'
                    udp_packet = UDPPacket(
                        src_ip=socket.inet_ntoa(ip.src), 
                        src_port=udp_layer.sport,
                        dst_ip=socket.inet_ntoa(ip.dst), 
                        dst_port=udp_layer.dport,
                        protocol=network_protocol, 
                        timestamp=ts, 
                        length=len(new_buf),
                        payloadbytes=len(udp_layer.data), 
                        header_size=len(ip.data) - len(udp_layer.data))
                
                    self.__add_packet_to_flow(udp_packet, flows, flows_lock)
                    if self.udp_packet_counter % self.__read_packets_count_value_log_info == 0:
                        print(f">> {self.udp_packet_counter} number of UDP packets has been processed...")
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, Exception) as e:
                    print(f"!! Exception happened in UDP packet processing!")
                    print(f"packet number: {self.packet_counter}")
                    print(e)
                    print(30*"*")
                    continue
    def capture(self, pcap_file: str, flows: list, flows_lock, thread_finished) -> list:
        print(">> UDP Parser has started...")
        if self.__continues_batch_mode is True:
            print(">> Continues Batch mode is on for UDP!")
            for i in range(self.__base_number_continues_files, self.__base_number_continues_files + self.__number_of_continues_files):
                filename = self.__continues_pcap_prefix + str(i)
                continues_pcap_file = os.path.join(self.__continues_batch_address, filename)
                self.pcap_parser(pcap_file=continues_pcap_file, flows=flows, flows_lock=flows_lock)
        else:
            self.pcap_parser(pcap_file=pcap_file, flows=flows, flows_lock=flows_lock)
        print(f">> End of parsing pcap file(s) for UDP flows.")
        print(f">>> {self.udp_packet_counter} UDP packets analyzed and {self.flows_counter} UDP flows created in total.")
        # Add any remaining flows
        with flows_lock:
            for flow in self.__finished_flows:
                flows.append(flow)
            for flow in self.__ongoing_flows.values():
                flows.append(flow)
            self.__finished_flows.clear()
            self.__ongoing_flows.clear()
        print(">> Preparing the UDP output file...")
        thread_finished.set(True)
    def __add_packet_to_flow(self, packet: UDPPacket, flows: list, flows_lock) -> None:
        flow_id_dict = self.__search_for_flow(packet)
        if flow_id_dict == None:
            self.__create_new_flow(packet)
            return
            
        flow = self.__ongoing_flows[flow_id_dict]
        if self.flow_is_ended(flow, packet):
            self.__finished_flows.append(flow)
            del self.__ongoing_flows[flow_id_dict]
            self.__create_new_flow(packet)
            if len(self.__finished_flows) >= self.__capturer_updating_flows_min_value:
                with flows_lock:
                    for ff in self.__finished_flows:
                        flows.append(ff)
                    self.__finished_flows.clear()
            if len(self.__ongoing_flows) >= self.__check_flows_ending_min_flows:
                for oflow_id in self.__ongoing_flows.copy():
                    oflow = self.__ongoing_flows[oflow_id]
                    if oflow.activity_timeout(packet):
                        self.__finished_flows.append(oflow)
                        del self.__ongoing_flows[oflow_id]
            return
        flow.add_packet(packet)
    def flow_is_ended(self, flow, packet):
        flow_duration = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_start_time()))
        active_time = datetime.fromtimestamp(float(packet.get_timestamp())) - datetime.fromtimestamp(float(flow.get_flow_last_seen()))
        
        # UDP flows end based on timeout or maximum duration (no FIN/RST flags like TCP)
        if flow_duration.total_seconds() > self.__max_flow_duration or active_time.total_seconds() > self.__activity_timeout:
            return True
        return False
    def __search_for_flow(self, packet) -> object:
        flow_id_dict = str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                       '_' + str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                       '_' + str(packet.get_protocol())
        alternative_flow_id_dict = str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                                   '_' + str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                                   '_' + str(packet.get_protocol())
        if alternative_flow_id_dict in self.__ongoing_flows:
            packet.forward = False
            return alternative_flow_id_dict
        if flow_id_dict in self.__ongoing_flows:
            return flow_id_dict
        return None
    def __create_new_flow(self, packet) -> None:
        self.flows_counter += 1
        new_flow = UDPFlow(packet, self.__activity_timeout)
        new_flow.add_packet(packet)
        flow_id_dict = str(packet.get_src_ip()) + '_' + str(packet.get_src_port()) + \
                       '_' + str(packet.get_dst_ip()) + '_' + str(packet.get_dst_port()) + \
                       '_' + str(packet.get_protocol())
        self.__ongoing_flows[flow_id_dict] = new_flow 
