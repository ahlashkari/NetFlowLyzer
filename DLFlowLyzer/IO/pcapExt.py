import pyshark
from tqdm import tqdm
from featureExt.ethFeatureExt import eth_pkt_feature_extractor
from featureExt.extraFeatureExt import llc_ext, dtp_ext,stp_ext,arp_ext,loop_ext,isl_ext,cdp_ext,dhcp_ext


def pcap_reader(PCAP_PATH, CAP_UDP,JUSTTCP, EXTERA, FEATURES):
    pcap = pyshark.FileCapture(PCAP_PATH, use_json=True)

    pkts_info_eth=list()
    pkts_info_extra = list()

    pkts_info_llc = list()
    pkts_info_stp = list()
    pkts_info_arp = list()
    pkts_info_loop = list()
    pkts_info_dtp = list()
    pkts_info_isl = list()
    pkts_info_cdp = list()
    pkts_info_dhcp = list()
    pkts_info_flow = list()


    for index, pkt in tqdm(enumerate(pcap)):
        proto = pkt.transport_layer

        if not CAP_UDP and proto == 'UDP':
            continue

        if JUSTTCP and proto != 'TCP':
            continue


        pkts_info_eth.append(eth_pkt_feature_extractor(pkt.ETH._all_fields,index, proto))


        extra_dict = {'pkt_num':index ,'frame_num':pkt.frame_info.number,
                                        'frame_len':pkt.frame_info.len, 'frame_cap_len':pkt.frame_info.cap_len,
                                        'frame_marked':pkt.frame_info.marked, 'frame_ignored':pkt.frame_info.ignored,
                                        'time_epoch':pkt.frame_info.time_epoch, 'time_utc':pkt.frame_info.time_utc, 'time_relative':pkt.frame_info.time_relative}

        if proto == 'UDP' or proto == 'TCP':
            try:
                flow_pred_dict = {'pkt_num':index ,'src_ip': pkt.ip._all_fields['ip.src'], 'dst_ip': pkt.ip._all_fields['ip.dst']}
            except:
                flow_pred_dict = {'pkt_num':index ,'src_ip': pkt.ipv6._all_fields['ipv6.src'], 'dst_ip': pkt.ipv6._all_fields['ipv6.dst']}


            try:
                flow_pred_dict['src_port'] = pkt.tcp._all_fields['tcp.srcport']
                flow_pred_dict['dst_port'] = pkt.tcp._all_fields['tcp.dstport']
                flow_pred_dict['tcp_syn'] = pkt.tcp._all_fields['tcp.flags_tree']['tcp.flags.syn']
                flow_pred_dict['tcp_ack'] = pkt.tcp._all_fields['tcp.flags_tree']['tcp.flags.ack']
                flow_pred_dict['tcp_fin'] = pkt.tcp._all_fields['tcp.flags_tree']['tcp.flags.fin']
                flow_pred_dict['tcp_res'] = pkt.tcp._all_fields['tcp.flags_tree']['tcp.flags.res']

                flow_pred_dict['tcp_stream'] = pkt.tcp._all_fields['tcp.stream']
                flow_pred_dict['tcp_ack_val'] = pkt.tcp._all_fields['tcp.ack']
                flow_pred_dict['tcp_seq_val'] = pkt.tcp._all_fields['tcp.seq']

                flow_pred_dict['tcp_syn_ack'] = 1 if int(flow_pred_dict['tcp_syn'])==1 and int(flow_pred_dict['tcp_ack'])==1 else 0
                flow_pred_dict['tcp_fin_ack'] = 1 if int(flow_pred_dict['tcp_fin']) == 1 and int(flow_pred_dict['tcp_ack']) == 1 else 0

            except:
                pass


            try:
                flow_pred_dict['src_port'] = pkt.udp._all_fields['udp.srcport']
                flow_pred_dict['dst_port'] = pkt.udp._all_fields['udp.dstport']
            except:
                pass

            pkts_info_flow.append(flow_pred_dict)

        if EXTERA:
            extra_dict['has_llc'] = 0
            extra_dict['has_dtp'] = 0
            extra_dict['has_stp'] = 0
            extra_dict['has_arp'] = 0
            extra_dict['has_dhcp'] = 0
            extra_dict['has_loop'] = 0
            extra_dict['has_cdp'] = 0
            extra_dict['has_isl'] = 0

            for item in ['llc', 'dtp', 'stp', 'arp', 'dhcp', 'loop', 'cdp']:
                if item in pkt.frame_info.protocols.split(':'):
                    if item == 'llc' and 'l' in FEATURES:
                        pkts_info_llc.append(llc_ext(pkt[item]._all_fields, index))
                        extra_dict['has_llc'] = 1
                    if item == 'dtp' and 'd' in FEATURES:
                        pkts_info_dtp.append(dtp_ext(pkt[item]._all_fields, index))
                        extra_dict['has_dtp'] = 1
                    if item == 'stp' and 's' in FEATURES:
                        pkts_info_stp.append(stp_ext(pkt[item]._all_fields, index))
                        extra_dict['has_stp'] = 1
                    if item == 'arp' and 'a' in FEATURES:
                        pkts_info_arp.append(arp_ext(pkt[item]._all_fields, index))
                        extra_dict['has_arp'] = 1
                    if item == 'dhcp' and 'h' in FEATURES:
                        pkts_info_dhcp.append(dhcp_ext(pkt[item]._all_fields, index))
                        extra_dict['has_dhcp'] = 1
                    if item == 'loop' and 't' in FEATURES:
                        pkts_info_loop.append(loop_ext(pkt[item]._all_fields, index))
                        extra_dict['has_loop'] = 1
                    if item == 'cdp' and 'c' in FEATURES:
                        pkts_info_cdp.append(cdp_ext(pkt[item]._all_fields, index))
                        extra_dict['has_cdp'] = 1

            if 'i' in FEATURES:
                try:
                    pkts_info_isl.append(isl_ext(pkt['isl']._all_fields, index))
                    extra_dict['has_isl'] = 1
                except:
                    extra_dict['has_isl'] = 0

        pkts_info_extra.append(extra_dict)
    return pkts_info_eth, pkts_info_extra,pkts_info_llc ,pkts_info_stp,pkts_info_arp,pkts_info_loop,pkts_info_dtp,pkts_info_isl,pkts_info_cdp,pkts_info_dhcp,pkts_info_flow
