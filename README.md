![NetFlowLyzer](bccc.jpg)

## Network Flow Analyzer (NetFlowLyzer)

NetFlowLyzer is an open-source, Python-based multi-layer network traffic analyzer for flow-based behavioral analysis from PCAP files. It is organized around the **TCP/IP model (four layers)** and provides **feature extraction for all four layers** through three integrated sub-packages and one unified command-line entry point (`netflowlyzer.py`).

### TCP/IP coverage (4 layers, 3 analyzers)

| TCP/IP layer | Name | Analyzer | Flag |
|--------------|------|----------|------|
| **4** | Application | [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer) | `-AL` |
| **3** | Transport | [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) | `-NTL` |
| **2** | Internet (Network) | [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) | `-NTL` |
| **1** | Link (Data link / network access) | [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer) | `-DL` |

**AL** covers TCP/IP **Application** (layer 4). **NTL** covers **Internet** and **Transport** (layers 2 and 3). **DL** covers the **Link** layer (layer 1). Running `-NTL -AL -DL` (or no layer flags) extracts features across the **full TCP/IP stack**.

```
TCP/IP stack          NetFlowLyzer
────────────────────────────────────
4  Application   →    ALFlowLyzer  (-AL)
3  Transport     →    NTLFlowLyzer (-NTL)
2  Internet      →    NTLFlowLyzer (-NTL)
1  Link          →    DLFlowLyzer  (-DL)
```

Together the three analyzers extract more than **1000** protocol-aware statistical and behavioral features from raw PCAP traffic. Processing is **offline** (PCAP in, CSV out), not live packet capture.

Unlike tools that focus on a single layer, NetFlowLyzer combines link-layer switching behavior, internet/transport flow characteristics, and application-level interactions in one workflow. It supports bidirectional flow generation, protocol-aware parsing, connection tracking, timing analysis, and behavioral profiling.

NetFlowLyzer targets cybersecurity research, AI/ML intrusion detection, encrypted traffic analysis, enterprise monitoring, malware analysis, threat hunting, and large-scale labeled dataset generation.

> **Note (OSI model):** Layer numbers in this project follow the **TCP/IP (DoD) model** above. In OSI terms, DL ≈ Layer 2, NTL ≈ Layers 3–4, and AL ≈ Layer 7 (presentation and session functions are folded into application-level analysis).

---

## Quick start

### Requirements

- **Python 3.10+** (3.11 recommended)
- **Wireshark** (for `-DL` only): `tshark` must be on your `PATH`  
  - Windows example: `C:\Program Files\Wireshark`

### Dependencies (Python packages)

Each TCP/IP layer has a requirements file at the repository root:

| File | Analyzer | TCP/IP layer(s) | Main packages |
|------|----------|-----------------|---------------|
| `requirements-ntl.txt` | NTLFlowLyzer | 2–3 (Internet + Transport) | scipy, multipledispatch, dpkt |
| `requirements-al.txt` | ALFlowLyzer | 4 (Application) | scipy, multipledispatch, python-whois, dpkt, scapy |
| `requirements-dl.txt` | DLFlowLyzer | 1 (Link) | numpy, pandas, pyshark, PyYAML, tqdm |

Install only the files for the layers you need, or install all three for full-stack analysis.

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/ahlashkari/NetFlowLyzer.git
cd NetFlowLyzer

# Full TCP/IP stack (all four layers)
pip install -r requirements-ntl.txt -r requirements-al.txt -r requirements-dl.txt
```

**Per layer (optional):**

```bash
pip install -r requirements-ntl.txt   # -NTL only
pip install -r requirements-al.txt      # -AL only
pip install -r requirements-dl.txt    # -DL only (also needs Wireshark/tshark)
```

> `requirements-dl.txt` matches `DLFlowLyzer/requirements.txt`. Use either path; the root file keeps the same layout as `requirements-ntl.txt` and `requirements-al.txt`.

### Run all four TCP/IP layers (all three analyzers)

```bash
# Defaults: input ../input, output ../output (relative to this repo)
python netflowlyzer.py -NTL -AL -DL
```

**Windows (PowerShell)** — add Wireshark to `PATH` for DL:

```powershell
$env:PATH = "C:\Program Files\Wireshark;" + $env:PATH
python netflowlyzer.py -NTL -AL -DL -i "..\input" -o "..\output"
```

### Run one PCAP file

```bash
python netflowlyzer.py -DL -i path/to/capture.pcap -o path/to/output
```

### Output files

For each input `basename.pcap`, selected layers write:

- `basename-NTL.csv`
- `basename-AL.csv`
- `basename-DL.csv`

Example: `2.pcap` → `2-NTL.csv`, `2-AL.csv`, `2-DL.csv` in the output folder.

---

## Command-line reference

```
python netflowlyzer.py [layer flags] [options]
```

| Option | Description |
|--------|-------------|
| `-NTL` | Run NTLFlowLyzer — TCP/IP **Internet + Transport** (layers 2–3) |
| `-AL` | Run ALFlowLyzer — TCP/IP **Application** (layer 4) |
| `-DL` | Run DLFlowLyzer — TCP/IP **Link** (layer 1) |
| *(no layer flags)* | Run all three analyzers (full TCP/IP stack) |
| `-i`, `--input`, `--input-dir` `PATH` | Folder of `.pcap` files **or** path to one `.pcap` |
| `-o`, `--output-dir` `DIR` | Output folder for CSV files (default: `../output`) |
| `-c`, `--config-file` | Optional base JSON config for NTL (paths overridden per run) |
| `--al-config` | Optional base JSON config for AL (paths overridden per run) |
| `--parallel` | Use multiple worker processes for AL/NTL (faster; more Windows Firewall prompts) |

**Defaults (recommended on Windows):** single-process mode for AL and NTL (one Python process, fewer firewall dialogs). WHOIS-related DNS features are disabled in unified runs to avoid extra network lookups.

**Layer order:** If you pass multiple flags, layers run in the order given on the command line (e.g. `-NTL -AL -DL`).

---

## Project layout

```
NetFlowLyzer/
├── netflowlyzer.py          # Unified entry point (all TCP/IP layers)
├── requirements-ntl.txt     # NTL — TCP/IP layers 2–3
├── requirements-al.txt      # AL  — TCP/IP layer 4
├── requirements-dl.txt      # DL  — TCP/IP layer 1
├── LICENSE.txt              # Project license (GPL-3.0)
├── ALFlowLyzer/             # TCP/IP layer 4 — Application
├── NTLFlowLyzer/            # TCP/IP layers 2–3 — Internet + Transport
└── DLFlowLyzer/             # TCP/IP layer 1 — Link (needs tshark)
```

Upstream standalone repositories remain available for layer-specific development and citation.

---

## Integrated analyzers

### [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer) — TCP/IP layer 4 (Application)

ALFlowLyzer extracts application-layer flow features from bidirectional flows: HTTP, HTTPS, DNS, MQTT, FTP, SMTP, SSH, Telnet, and related protocols. Install with `pip install -r requirements-al.txt`. It supports application-layer intrusion detection, encrypted traffic analysis, malware communication profiling, and ML-driven behavioral analytics.

### [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) — TCP/IP layers 2–3 (Internet + Transport)

NTLFlowLyzer extracts flow features from the internet and transport layers: IP, TCP, UDP, ICMP, QUIC, and related protocols, with statistical, temporal, directional, and behavioral features per bidirectional flow. Install with `pip install -r requirements-ntl.txt`. It is aimed at intrusion detection, DDoS analysis, anomaly detection, traffic classification, and large-scale security analytics.

### [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer) — TCP/IP layer 1 (Link)

DLFlowLyzer performs link-layer analysis for enterprise switching environments: Ethernet, ARP, STP, CDP, DHCP, DTP, ISL, LLC, VLAN-related traffic, and other control-plane protocols. It supports link-layer behavioral profiling, attack detection, and switching-protocol analysis. Install with `pip install -r requirements-dl.txt`. DL uses **pyshark** / **tshark** and is slower on large PCAPs than AL/NTL.

---

## Tips

- **Large PCAPs:** DL can take a long time (tens of minutes per file). Test with `-NTL` or `-AL` first, or a single file via `-i capture.pcap`.
- **Windows Firewall:** Allow Python once when prompted; use default single-process mode (do not pass `--parallel`) to minimize repeated prompts. You may also need to allow `tshark.exe` once for DL.
- **Configs:** Layer-specific defaults live in `ALFlowLyzer/config.json` and `NTLFlowLyzer/config.json`. NetFlowLyzer writes temporary configs per run with the correct PCAP and CSV paths.

---

## Project team

* [**Arash Habibi Lashkari**](http://ahlashkari.com/index.asp) — Founder and supervisor

**ALFlowLyzer**

* [**Moein Shafi**](https://github.com/moein-shafi) — Graduate student, researcher and developer, York University
* [**Hardik Mohanty**](https://github.com/hardhik-99) — Mitacs GRI, researcher and developer, York University

**NTLFlowLyzer**

* [**Moein Shafi**](https://github.com/moein-shafi) — Graduate student, researcher and developer, York University (2022–2024)
* [**Mohamed Aziz El Fadhel**](https://github.com/MohamedAzizFadhel) — Mitacs Global Research Intern, York University (2024)
* [**Sepideh Niktabe**](https://github.com/sepideh2020) — Graduate student, York University (2022–2023)
* [**Mehrsa Khoshpasand**](https://github.com/Khoshpasand-mehrsa) — Research assistant, York University (2022)
* [**Parisa Ghanad**](https://github.com/parishisit) — Volunteer researcher (2022)

**DLFlowLyzer**

* [**Amirhossein Ahmadnejad Roudsari**](https://github.com/aahmadnejad) — Graduate researcher and developer, York University (2024–2025)

---

## Acknowledgement

This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada (NSERC, #RGPIN-2020-04701) and the Canada Research Chair (Tier II, #CRC-2021-00340) held by Arash Habibi Lashkari.

---

## License

NetFlowLyzer is released under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE.txt](LICENSE.txt) in the repository root.

This project integrates code from [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer), [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer), and [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer). Each upstream repository may define its own license terms; `DLFlowLyzer/LICENSE` is also included under the bundled `DLFlowLyzer/` folder.
