import numpy as np

def eth_pkt_feature_extractor(data, index, connection):
    res=dict()
    res['pkt_num'] = index

    try: res['connection']= connection
    except: res['connection']= np.nan

    try: res['dist_addr']=data['eth.dst']
    except: res['dist_addr']= np.nan

    try: res['dist_addr_vendor']=data['eth.dst'][:8]
    except: res['dist_addr_vendor']= np.nan

    try: res['dist_addr_device']=data['eth.dst'][9:]
    except: res['dist_addr_device']= np.nan

    try: res['dist_addr_vendor_name']=data['eth.dst_tree']['eth.addr.oui_resolved']
    except: res['dist_addr_vendor_name']= 'BROADCAST' if res['dist_addr'] == 'ff:ff:ff:ff:ff:ff' else 'UNKNOWN'

    try: res['dist_addr_vendor_name_known']= 0 if res['dist_addr_vendor_name'] == 'UNKNOWN' else 1
    except: res['dist_addr_vendor_name_known']= np.nan

    try: res['dist_ig']= data['eth.dst_tree']['eth.dst.ig']
    except: res['dist_ig']= np.nan

    try: res['dist_lg']= data['eth.dst_tree']['eth.dst.lg']
    except: res['dist_lg']= np.nan

    try: res['dist_oui']= data['eth.dst_tree']['eth.dst.oui']
    except: res['dist_oui']= np.nan

    try: res['src_addr']=data['eth.src']
    except: res['src_addr']= np.nan

    try: res['src_addr_vendor']=data['eth.src'][:8]
    except: res['src_addr_vendor']= np.nan

    try: res['src_addr_device']=data['eth.src'][9:]
    except: res['src_addr_device']= np.nan

    try: res['src_addr_vendor_name']=data['eth.src_tree']['eth.addr.oui_resolved']
    except: res['src_addr_vendor_name']='BROADCAST' if res['src_addr'] == 'ff:ff:ff:ff:ff:ff' else 'UNKNOWN'

    try: res['src_addr_vendor_name_known']= 0 if res['dist_addr_vendor_name'] == 'UNKNOWN' else 1
    except: res['srs_addr_vendor_name_known']= np.nan

    try: res['src_ig']= data['eth.src_tree']['eth.src.ig']
    except: res['src_ig']= np.nan

    try: res['src_lg']= data['eth.src_tree']['eth.src.lg']
    except: res['src_lg']= np.nan

    try: res['src_oui']= data['eth.src_tree']['eth.src.oui']
    except: res['src_oui']= np.nan

    try: res['eth_type']= data['eth.type']
    except: res['eth_type']= np.nan

    return res