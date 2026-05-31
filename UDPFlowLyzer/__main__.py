#!/usr/bin/env python3

import argparse
import glob
import os

from .config_loader import ConfigLoader
from .udp_network_flow_analyzer import UDPNetworkFlowAnalyzer

def args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='UDPFlowLyzer')
    parser.add_argument('-c', '--config-file', action='store', help='Json config file address.')
    parser.add_argument('-o', '--online-capturing', action='store_true',
                        help='Capturing mode. The default mode is offline capturing.')
    parser.add_argument('-b', '--batch-mode', action='store_true',
                        help='Analyze all the files in the given directory. The default is False.')
    parser.add_argument('-cb', '--continues-batch-mode', action='store_true',
                        help='Continues batch mode. Analyze files in the given directory continuously.'
                            ' Default is False.')
    return parser


def find_pcap_files(directory):
    file_pattern = directory + '/*'
    pcap_files = glob.glob(file_pattern)
    return pcap_files


def main():
    print("You initiated UDPFlowLyzer!")
    parsed_arguments = args_parser().parse_args()
    config_file_address = "./UDPFlowLyzer/config.json" if parsed_arguments.config_file is None else parsed_arguments.config_file
    config = ConfigLoader(config_file_address)

    if not parsed_arguments.batch_mode:
        udp_analyzer = UDPNetworkFlowAnalyzer(config, parsed_arguments.continues_batch_mode)
        udp_analyzer.run()
        return

    print(">> Batch mode is on!")
    batch_address = config.batch_address
    batch_address_output = config.batch_address_output
    pcap_files = find_pcap_files(batch_address)

    # Sort files to ensure consistent processing order
    pcap_files.sort()

    print(f">> {len(pcap_files)} number of files detected. Lets go for analyzing them!")
    for file in pcap_files:
        print(100*"#")
        output_file_name = os.path.basename(file)
        # Keep the unique suffix/index if the file name ends with .pcap1, .pcap2, ...
        base_name, extension = os.path.splitext(output_file_name)
        if extension.lower() != ".pcap":
            output_file_name = f"{base_name}{extension}"
        else:
            output_file_name = base_name

        config.pcap_file_address = file
        config.udp_output_file_address = os.path.join(batch_address_output, f"{output_file_name}_udp.csv")
        print(f">> UDP output will be written to: {config.udp_output_file_address}")

        udp_analyzer = UDPNetworkFlowAnalyzer(config, parsed_arguments.continues_batch_mode)
        udp_analyzer.run()


if __name__ == "__main__":
    main()
