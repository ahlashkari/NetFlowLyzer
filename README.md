## Network Flow Analyzer (NetFlowLyzer)

NetFlowLyzer is an open-source, Python-based multi-layer network traffic analyzer designed for comprehensive flow-based behavioral analysis across the four major layers of modern network communications: Data Link Layer, Network Layer, Transport Layer, and Application Layer. The framework integrates multiple specialized analyzers into a unified traffic analysis platform capable of extracting more than 1000 protocol-aware statistical and behavioral features from raw PCAP traffic in real time.

Unlike traditional traffic analyzers that focus on isolated protocol layers, NetFlowLyzer provides a holistic multi-layer perspective of network behavior by combining Layer-2 switching protocols, Layer-3/4 communication characteristics, and Layer-7 application-level interactions within a unified feature extraction framework. The analyzer supports bidirectional flow generation, protocol-aware parsing, connection tracking, entropy analysis, timing analysis, and behavioral profiling across multiple network layers simultaneously.

NetFlowLyzer is designed to support cybersecurity research, AI/ML-based intrusion detection systems, encrypted traffic analysis, enterprise traffic monitoring, malware analysis, threat hunting, behavioral profiling, and large-scale cybersecurity dataset generation for modern enterprise, IoT, cloud, SDN, and next-generation network environments.

### Application Layer Flow Analyzer (ALFlowLyzer)
ALFlowLyzer focuses on extracting application-layer flow-based features from network traffic. The analyzer reconstructs bidirectional application flows and extracts protocol-aware statistical, timing, and behavioral features from protocols such as HTTP, HTTPS, DNS, MQTT, FTP, SMTP, SSH, Telnet, and other application-level communications. ALFlowLyzer is designed to support application-layer intrusion detection, encrypted traffic analysis, malware communication profiling, and AI/ML-driven behavioral analytics.

### Transport and Network Layers Flow Analyzer (NTLFlowLyzer)
NTLFlowLyzer is responsible for extracting flow-based features from the Network and Transport layers. The analyzer supports TCP, UDP, ICMP, QUIC, and IP-level traffic analysis while generating rich statistical, temporal, directional, and behavioral features from bidirectional network flows. The framework is designed for intrusion detection, DDoS analysis, anomaly detection, traffic classification, and large-scale AI-driven cybersecurity analytics.

### Data Link Layer Flow Analyzer (DLLFlowLyzer)
DLLFlowLyzer focuses on Data Link Layer behavioral analysis and feature extraction. The analyzer supports Layer-2 protocols and enterprise switching environments, including ARP, STP, CDP, DHCP, DTP, ISL, LLC, VLAN-related traffic, and other switching/control-plane communications. DLLFlowLyzer enables protocol-aware behavioral profiling and flow generation for enterprise network security, Layer-2 intrusion detection, attack detection, switching protocol analysis, and AI-based behavioral monitoring of modern enterprise infrastructures.



## Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor
For ALFlowLyzer:
* [**Moein Shafi:**](https://github.com/moein-shafi) Graduate student, Researcher and developer - York University
* [**Hardik Mohanty:**](https://github.com/hardhik-99) Mitacs Global Research Internship (GRI), Researcher and developer - York University
For NTLFlowLyzer:
* [**Moein Shafi:**](https://github.com/moein-shafi) Graduate student, Researcher and developer - York University ( 2 years, 2022 - 2024)
* [**Mohamed Aziz El Fadhel:**](https://github.com/MohamedAzizFadhel) Mitacs Global Research Intern, Researcher and developer - York University (4 months, 2024-2024)
* [**Sepideh Niktabe:**](https://github.com/sepideh2020) Graduate students, Researcher and developer - York University (6 months, 2022-2023)
* [**Mehrsa Khoshpasand:**](https://github.com/Khoshpasand-mehrsa) Researcher Assistant (RA) - York University (3 months, 2022)
* [**Parisa Ghanad:**](https://github.com/parishisit) Volunteer Researcher and developer (4 months, 2022)
For DLLFlowLyzer:
* [**Amirhossein Ahmadnejad Roudsari:**](https://github.com/aahmadnejad) Graduate researcher and developer - York University (2024-2025)

## Acknowledgement
This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.
