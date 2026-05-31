#!/usr/bin/env python3

from datetime import datetime
from .features_udp import get_all_features
import warnings

class UDPFeatureExtractor(object):
    def __init__(self, floating_point_unit: str):
        warnings.filterwarnings("ignore")
        self.floating_point_unit = floating_point_unit
        
        # Get all UDP features from the registry
        self.__udp_features = get_all_features()
        
        # Set floating point unit for all features
        for feature in self.__udp_features:
            feature.floating_point_unit = floating_point_unit

    def execute(self, data: list, data_lock, flows: list, features_ignore_list: list = [],
            label: str = "") -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            self.__extracted_data = []
            for flow in flows:
                features_of_flow = {}
                features_of_flow["flow_id"] = str(flow)
                features_of_flow["timestamp"] = datetime.fromtimestamp(float(flow.get_timestamp()))
                features_of_flow["src_ip"] = flow.get_src_ip()
                features_of_flow["src_port"] = flow.get_src_port()
                features_of_flow["dst_ip"] = flow.get_dst_ip()
                features_of_flow["dst_port"] = flow.get_dst_port()
                features_of_flow["protocol"] = flow.get_protocol()
                
                # Extract UDP features
                for feature in self.__udp_features:
                    if feature.name in features_ignore_list:
                        continue
                    try:
                        features_of_flow[feature.name] = feature.extract(flow)
                    except Exception as e:
                        print(f">>> Error occurred in extracting the '{feature.name}' for '{flow}' UDP flow.")
                        print(f">>> Error message: {e}")
                        print(110*"=")
                        features_of_flow[feature.name] = None
                        continue
                        
                features_of_flow["label"] = label
                self.__extracted_data.append(features_of_flow.copy())
                
            with data_lock:
                data.extend(self.__extracted_data) 