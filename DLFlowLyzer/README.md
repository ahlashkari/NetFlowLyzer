# Data Link Flow Analyzer (DLFlowLyzer)
Data Link Flow Lyzer

## Run and Structure
 
### Run
first install requirements from requrements.txt as follow:
```shell 
pip install -r requirements.txt
```

Options:
 - -U / --UDP : extract features from udp in addition to TCP packets. (false)
 - -P / --pcap : path to pcap file. (./test.pcap)
 - -R / --result : results base csv file name. (Final)
 - -S / --save : save results folder name. (Res)
 - -J / --justTCP : just extract TCP packets Data Link features. (false)
 - -E / --extra : extract all extra features from pcap include llc,stp,arp,loop,dtp,isl,cdp,dhcp. (false)
 - -F / --features : which extra features you need to extract. use this keyword to specify them. for instance: <-F latc> to capture llc, arp, loop, cdp. the keys are l(llc), s(stp), a(arp), t(loop), d(dtp), i(isl), c(cdp), h(dhcp). (lsatdich)
 
 example:
```shell
 python main.py -UP ./test.pcap -S myFeatures -R testing 
 ```
**note**: the default value for options is in parentheses.

### structure:
 - **main.py** : main program - calling functions from other files and get arguments from user.
 - **IO**: input and output functions - read PCAP and save CSV.
   - **csvSave.py**: this file save given data in csv file (files). the given data are frame, eth, protocols and flow features.
   - **pcapExt.py**: extract raw data from packets in pcap file, returning multiple dictionaries to main.py to save them in csv files calling function from csvSave.py (eth, protocols, all). protocols includes: llc, stp, arp, loop, dtp, isl, cdp and dhcp.
 - **featureExt**: extracting features functions - eth and flow feature extractor.
   - **flowFeatureExt.py**: extract features from flows. include raw features and statistical features. 
   - **ethFeatureExt**: extract basic features of eth.(raw)
   - **extraFeatureExt**: extract data link layer protocols and formats if the Extra argument activated.
**note**: in saved csv file you can see the keywords eth, protocols, all, final_flow which are refering to the csv file material.

## flow features

|                         |                          |                           |                          |                                |                                |                          |
|:-----------------------:|:------------------------:|:-------------------------:|:------------------------:|:------------------------------:|:------------------------------:|:------------------------:|
| eth_one_addr            | eth_one_addr_vendor      | eth_one_addr_device       | eth_one_addr_vendor_name | eth_one_addr_vendor_name_known | eth_one_ig                     | eth_one_lg               |
| eth_one_oui             | eth_two_addr             | eth_two_addr_vendor       | eth_two_addr_device      | eth_two_addr_vendor_name       | eth_two_addr_vendor_name_known | eth_two_ig               |
| eth_two_lg              | eth_two_oui              | eth_type                  | connection               | time_delta                     | sum_frame_len                  | sum_frame_len_div_time   |
| num_frame_marked        | num_frame_ignored        | num_llc_frame             | num_dtp_frame            | num_stp_frame                  | num_arp_frame                  | num_dhcp_frame           |   |
|  num_loop_frame         | num_cdp_frame            | num_isl_frame             | percent_frame_marked     | percent_frame_ignored          | percent_llc_frame              | percent_dtp_frame        |
| percent_stp_frame       | percent_arp_frame        | percent_dhcp_frame        | percent_loop_frame       | percent_cdp_frame              | percent_isl_frame              | sum_frames_mac1_mac2     |
| mean_frames_mac1_mac2   | max_frames_mac1_mac2     | min_frames_mac1_mac2      | median_frames_mac1_mac2  | std_frames_mac1_mac2           | norm_frames_mac1_mac2          | sum_frames_mac2_mac1     |   |
| mean_frames_mac2_mac1   | max_frames_mac2_mac1     | min_frames_mac2_mac1      | median_frames_mac2_mac1  | std_frames_mac2_mac1           | norm_frames_mac2_mac1          | mean_frame_len           |
| max_frame_len           | min_frame_len            | median_frame_len          | std_frame_len            | norm_frame_len                 | mean_llc_ssap_sap              | max_llc_ssap_sap         |   |
| min_llc_ssap_sap        | median_llc_ssap_sap      | std_llc_ssap_sap          | norm_llc_ssap_sap        | sum_llc_dsap_sap               | mean_llc_dsap_sap              | max_llc_dsap_sap         |
| min_llc_dsap_sap        | median_llc_dsap_sap      | std_llc_dsap_sap          | norm_llc_dsap_sap        | mean_llc_ssap_cr               | mean_llc_dsap_cr               | sum_stp_msg_age          |
| mean_stp_msg_age        | max_stp_msg_age          | min_stp_msg_age           | median_stp_msg_age       | std_stp_msg_age                | norm_stp_msg_age               | sum_stp_forward          |   |
| mean_stp_forward        | max_stp_forward          | min_stp_forward           | median_stp_forward       | std_stp_forward                | norm_stp_forward               | count_stp_flags_tc_1     |   |
| count_stp_flags_tcack_1 | percent_stp_flags_tc_1   | percent_stp_flags_tcack_1 | stp_age_div_max_age      | sum_loop_skipcount             | sum_dtp_tlvs                   | mean_isl_bpdu            |
| sum_isl_len             | mean_isl_len             | max_isl_len               | min_isl_len              | median_isl_len                 | std_isl_len                    | norm_isl_len             |
| sum_cdp_addresses_count | mean_cdp_addresses_count | max_cdp_addresses_count   | min_cdp_addresses_count  | median_cdp_addresses_count     | std_cdp_addresses_count        | norm_cdp_addresses_count |
| sum_cdp_tlvs            | sum_cdp_capabilities     | mean_cdp_power_sum        | max_cdp_power_sum        | min_cdp_power_sum              | median_cdp_power_sum           | std_cdp_power_sum        |
| norm_cdp_power_sum      |


# ProjectTeammembers 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Amirhossein Ahmadnejad Roudsari**](https://github.com/aahmadnejad) Graduate researcher and developer 

# Acknowledgement
This project has been made possible through funding from Mitacs Global Research Internship (GRI), the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.
