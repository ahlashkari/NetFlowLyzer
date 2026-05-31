![NetFlowLyzer](bccc.jpg)

## Network Flow Analyzer (NetFlowLyzer)

NetFlowLyzer is an open-source, Python-based multi-layer network traffic analyzer for flow-based behavioral analysis from PCAP files. Unlike tools that focus on a single layer or a single transport protocol, NetFlowLyzer covers the **full TCP/IP stack**—**Link** (`-DL`), **Internet** and **TCP** transport (`-NTL`), **Application** (`-AL`), plus **UDP** (`-U`) and **QUIC** (`-Q`) transport flows—in one unified offline workflow. It combines link-layer switching behavior, internet and transport flow characteristics across TCP, UDP, and QUIC, and application-level protocol interactions and provides **feature extraction for all four layers both TCP and UDP** through integrated sub-packages and one unified command-line entry point (`netflowlyzer.py`). NetFlowLyzer supports bidirectional flow generation, protocol-aware parsing, connection tracking, timing analysis, and behavioral profiling.

### TCP and UDP coverage (4 layers)

| TCP/IP layer | Name | Analyzer | Flag |
|--------------|------|----------|------|
| **4** | Application | [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer) | `-AL` |
| **3** | Transport (TCP) | [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) | `-NTL` |
| **3** | Transport (UDP) | [UDPFlowLyzer](https://github.com/ahlashkari/UDPFlowLyzer) | `-U` |
| **3** | Transport (QUIC) | [QUICFlowLyzer](https://github.com/ahlashkari/QUICFlowLyzer) | `-Q` |
| **2** | Internet (Network) | [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) | `-NTL` |
| **1** | Link (Data link / network access) | [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer) | `-DL` |

**ALFlowLyzer** (`-AL`) covers TCP/IP **Application** (layer 4). **NTLFlowLyzer** (`-NTL`) covers **Internet** and **TCP-focused transport** (layers 2–3). **DLFlowLyzer** (`-DL`) covers the **Link** layer (layer 1). **QUICFlowLyzer** (`-Q`) adds **QUIC** transport features (bundled in this repo). **UDPFlowLyzer** (`-U`) provides dedicated **UDP** transport features (bundled in this repo).

Running `-NTL -AL -DL` (or no layer flags) extracts features across the **core TCP/IP stack**. Add **`-Q`** for QUIC or **`-U`** for UDP when the capture needs those transport analyzers.

```
TCP/IP stack          NetFlowLyzer
────────────────────────────────────
4  Application   →    ALFlowLyzer     (-AL)
3  Transport     →    NTLFlowLyzer    (-NTL)   TCP + Internet
                 →    UDPFlowLyzer    (-U)
                 →    QUICFlowLyzer   (-Q)     QUIC
2  Internet      →    NTLFlowLyzer    (-NTL)
1  Link          →    DLFlowLyzer     (-DL)
```

Together the five analyzers extract more than **1000** protocol-aware statistical and behavioral features from raw PCAP traffic. Processing is **offline** (PCAP in, CSV out), not live packet capture.

NetFlowLyzer targets cybersecurity research, AI/ML intrusion detection, encrypted traffic analysis, enterprise monitoring, malware analysis, threat hunting, and large-scale labeled dataset generation.

> **Note (OSI model):** Layer numbers in this project follow the **TCP/IP (DoD) model** above. In OSI terms, DL ≈ Layer 2, NTL ≈ Layers 3–4, and AL ≈ Layer 7 (presentation and session functions are folded into application-level analysis).

---

## Quick start

### Requirements

- **Python 3.10+** (3.11 recommended)
- **Wireshark / TShark** (for `-DL` only) — see [TShark and PyShark (`-DL`)](#tshark-and-pyshark-dl) below

### TShark and PyShark (`-DL`)

DLFlowLyzer needs **two** pieces for link-layer analysis:

| Piece | What it is | How you get it |
|-------|------------|----------------|
| **PyShark** | Python wrapper used by DLFlowLyzer | `pip install -r requirements-dl.txt` |
| **TShark** | Wireshark CLI that actually parses PCAPs | [Wireshark installer](https://www.wireshark.org/download.html) (enable **TShark** during setup) |

PyShark does **not** replace TShark. Without a real `tshark` binary, `-DL` will fail even if PyShark is installed.

**Windows:** When you run `python netflowlyzer.py -DL`, NetFlowLyzer calls `ensure_tshark_on_path()` and prepends `C:\Program Files\Wireshark` to `PATH` for that process if the folder exists. You usually **do not** need to edit system `PATH` manually for `-DL` on a default Wireshark install.

**Verify TShark** (optional — useful in a fresh terminal):

```powershell
# Default install location (Windows)
& "C:\Program Files\Wireshark\tshark.exe" -v

# Or, if Wireshark is on PATH:
tshark -v
```

**Manual `PATH`** (Linux, macOS, or a non-default Wireshark location):

```bash
# Linux example
export PATH="/usr/bin:$PATH"   # or wherever tshark lives
which tshark && tshark -v
```

```powershell
# Windows — only if Wireshark is not under C:\Program Files\Wireshark
$env:PATH = "C:\Program Files\Wireshark;" + $env:PATH
```

On Windows you may need to allow **`tshark.exe`** through the firewall once when DL runs.

### Dependencies (Python packages)

Each TCP/IP layer has a requirements file at the repository root:

| File | Analyzer | TCP/IP layer(s) | Main packages |
|------|----------|-----------------|---------------|
| `requirements-ntl.txt` | NTLFlowLyzer | 2–3 (Internet + Transport) | scipy, multipledispatch, dpkt |
| `requirements-al.txt` | ALFlowLyzer | 4 (Application) | scipy, multipledispatch, python-whois, dpkt, scapy |
| `requirements-dl.txt` | DLFlowLyzer | 1 (Link) | numpy, pandas, pyshark, PyYAML, tqdm |
| `requirements-u.txt` | UDPFlowLyzer | 3 (Transport — UDP) | scipy, multipledispatch, dpkt |
| `requirements-q.txt` | QUICFlowLyzer | 3 (Transport — QUIC) | dpkt |

For **UDP** analysis, install `requirements-u.txt` (bundled `UDPFlowLyzer/` package).

Install only the files for the layers you need, or install all three core files for full-stack analysis (`-NTL`, `-AL`, `-DL`).

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
pip install -r requirements-q.txt     # -Q only (QUIC transport)
pip install -r requirements-u.txt     # -U only (UDP transport)
```

**Transport add-ons (UDP / QUIC):**

```bash
# QUIC (integrated in NetFlowLyzer)
pip install -r requirements-q.txt
python netflowlyzer.py -Q -i path/to/capture.pcap -o path/to/output

# UDP (integrated in NetFlowLyzer)
pip install -r requirements-u.txt
python netflowlyzer.py -U -i path/to/capture.pcap -o path/to/output
```

> `requirements-dl.txt` matches `DLFlowLyzer/requirements.txt`. Use either path; the root file keeps the same layout as `requirements-ntl.txt` and `requirements-al.txt`.

### Run all four TCP/IP layers (all three analyzers)

```bash
# Defaults: input ../input, output ../output (relative to this repo)
# AL: DNS features on, WHOIS off; use --al-no-dns for quietest runs
python netflowlyzer.py -NTL -AL -DL
```

**Windows:** `-DL` auto-adds `C:\Program Files\Wireshark` to `PATH` for that run (see [TShark and PyShark](#tshark-and-pyshark-dl)). No extra `PATH` step is required if Wireshark is installed in the default folder.

```powershell
python netflowlyzer.py -NTL -AL -DL -i "..\input" -o "..\output"
```

### AL: DNS and WHOIS options

ALFlowLyzer splits DNS-related work into three groups:

| Group | Count (approx.) | When it runs | CLI |
|-------|-----------------|--------------|-----|
| **General AL** | ~100+ features | All flows (HTTP, DNS, TCP, UDP, …) | *(always on with `-AL`)* |
| **DNS / domain** | ~37 features | **DNS flows only** (port 53 / DNS protocol) | On by default; `--al-no-dns` to disable |
| **WHOIS lookups** | 14 features | DNS flows only, when enabled | `--al-whois` to enable (off by default) |

**Recommended modes:**

| Goal | Command |
|------|---------|
| Default — DNS columns, no live WHOIS | `python netflowlyzer.py -AL -i "..\input" -o "..\output"` |
| Quiet AL — timing/size stats only, no DNS columns | `python netflowlyzer.py -AL --al-no-dns -i "..\input" -o "..\output"` |
| Full DNS + live WHOIS (slow, needs network) | `python netflowlyzer.py -AL --al-whois -i "..\input" -o "..\output"` |

**Examples:**

```powershell
# AL without WHOIS (default)
python netflowlyzer.py -AL -i "..\input\2.pcap" -o "..\output"

# Same as default, explicit
python netflowlyzer.py -AL --al-no-whois -i "..\input\2.pcap" -o "..\output"

# AL with WHOIS lookups enabled (opt-in)
python netflowlyzer.py -AL --al-whois -i "..\input\2.pcap" -o "..\output"

# Quiet AL — no DNS/domain columns at all
python netflowlyzer.py -AL --al-no-dns -i "..\input\2.pcap" -o "..\output"
```

**Flag rules:**

- `--al-no-whois` and `--al-whois` are **mutually exclusive**. If neither is passed, WHOIS stays disabled.
- `--al-no-dns` disables **all** DNS/domain features (~52 columns, including WHOIS). It takes precedence over `--al-whois`.
- DNS/domain extractors run only on flows classified as **DNS**; TCP and UDP flows skip those columns automatically.
- Feature extraction errors are **summarized once per flow** in the terminal instead of printing one line per failed feature.

### Run one PCAP file

```bash
python netflowlyzer.py -DL -i path/to/capture.pcap -o path/to/output
```

### Output files

For each input `basename.pcap`, selected layers write:

- `basename-NTL.csv`
- `basename-AL.csv`
- `basename-DL.csv`
- `basename-Q.csv` (when `-Q` is selected)
- `basename-U.csv` (when `-U` is selected)

Example: `2.pcap` with `-NTL -AL -DL -Q` → `2-NTL.csv`, `2-AL.csv`, `2-DL.csv`, `2-Q.csv` in the output folder.

When a layer finishes, NetFlowLyzer prints a unified summary such as `[NTL] 1234 TCP transport flow(s) written to ...` or a zero-flow warning when the CSV has headers only.

---

## Recommended workflows

| Goal | Command |
|------|---------|
| Quick AL smoke test (fast, no DNS columns) | `python netflowlyzer.py -AL --al-no-dns -i one.pcap -o out` |
| Core TCP stack (default) | `python netflowlyzer.py -i folder -o out` |
| All transport analyzers on one capture | `python netflowlyzer.py -NTL -U -Q -i one.pcap -o out` |
| QUIC / cloud VXLAN capture | `python netflowlyzer.py -Q --q-vxlan-ip 10.0.0.1 -i one.pcap -o out` |
| Full stack including link layer | `python netflowlyzer.py -NTL -AL -DL -i one.pcap -o out` |
| UDP-only transport features | `python netflowlyzer.py -U -i one.pcap -o out` |

**Runtime tip:** On large PCAPs, `-DL` is usually the slowest step. Run `-NTL`, `-AL`, `-Q`, or `-U` first for faster feedback; add `-DL` when you need link-layer features.

### Input formats (`.pcap` / `.pcapng`)

`-i` accepts a folder of capture files or a single file with a **`.pcap`** or **`.pcapng`** extension. Folder scans include both extensions. **`-Q`** reads PCAPNG internally when given a path; other layers use dpkt and accept PCAPNG where dpkt supports it for that file.

---

## `--parallel` matrix

| Layer | Flag | Respects `--parallel` | Default |
|-------|------|------------------------|---------|
| Application | `-AL` | Yes | Single-process (threads in one Python process) |
| TCP transport | `-NTL` | Yes | Single-process |
| UDP transport | `-U` | Yes | Single-process |
| QUIC transport | `-Q` | No — always in-process | n/a |
| Link | `-DL` | No — always in-process | n/a |

Pass **`--parallel`** only when you need maximum speed on AL/NTL/U and can tolerate extra Windows Firewall prompts (many Python worker processes). Default single-process mode is recommended on Windows.

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
| `-Q` | Run QUICFlowLyzer — QUIC transport features (header-level, no decryption) |
| `-U` | Run UDPFlowLyzer — UDP transport features |
| *(no layer flags)* | Run all three analyzers (full TCP/IP stack) |
| `-i`, `--input`, `--input-dir` `PATH` | Folder of `.pcap` / `.pcapng` files **or** path to one capture file |
| `-o`, `--output-dir` `DIR` | Output folder for CSV files (default: `../output`) |
| `-c`, `--config-file` | Optional base JSON config for NTL (paths overridden per run) |
| `--udp-config` | Optional base JSON config for UDP (paths overridden per run) |
| `--al-config` | Optional base JSON config for AL (paths overridden per run) |
| `--al-no-whois` | Disable WHOIS DNS features in AL (default when `-AL` is used) |
| `--al-whois` | Enable WHOIS DNS lookups in AL (slow; requires network; may error) |
| `--al-no-dns` | Disable **all** DNS/domain features in AL (~52 columns; general AL stats only) |
| `--parallel` | Use multiple worker processes for **AL / NTL / U only** (faster; more Windows Firewall prompts) |
| `--q-vxlan-ip` `IP` | QUIC (-Q): VXLAN outer IP filter (cloud/mirrored captures) |
| `--q-vxlan-port` `PORT` | QUIC (-Q): VXLAN UDP port (default: 4789) |
| `--q-allow-mirrored-sport` | QUIC (-Q): allow AWS-style mirrored VXLAN source port |
| `--q-inner-cidr` `CIDR` | QUIC (-Q): inner CIDR filter after VXLAN decap (repeatable) |
| `--q-idle-gap-sec` `SEC` | QUIC (-Q): idle gap for active/idle episode stats (default: 1.0) |
| `--q-verbose` | QUIC (-Q): per-packet QUIC parsing logs (default: quiet) |

**AL defaults (recommended on Windows):** single-process mode for AL and NTL (one Python process, fewer firewall dialogs). With `-AL`, DNS/domain features run on DNS flows only; WHOIS stays **off** unless you pass `--al-whois`. Use `--al-no-dns` for the quietest AL runs (no domain, TTL, or WHOIS columns).

**QUIC (-Q):** Runs in-process (same Python as NetFlowLyzer). Default is **quiet** progress (every 10k packets). PCAPs with **no QUIC traffic** still produce `{basename}-Q.csv` with **headers only** and an empty **`label`** column — NetFlowLyzer warns when zero flows are found. Use VXLAN flags for cloud captures; see QUIC section below.

**UDP (-U):** Same zero-flow behavior as `-Q` — captures with no UDP traffic may produce `{basename}-U.csv` with **headers only**; NetFlowLyzer prints a zero-flow warning.

**Layer order:** If you pass multiple flags, layers run in the order given on the command line (e.g. `-NTL -AL -DL`).

---

## Project layout

```
NetFlowLyzer/
├── netflowlyzer.py          # Unified entry point (all TCP/IP layers)
├── requirements-ntl.txt     # NTL — TCP/IP layers 2–3
├── requirements-al.txt      # AL  — TCP/IP layer 4
├── requirements-dl.txt      # DL  — TCP/IP layer 1
├── requirements-u.txt       # U   — UDP transport (-U)
├── requirements-q.txt       # Q   — QUIC transport (-Q)
├── LICENSE                  # Project license (GPL-3.0)
├── ALFlowLyzer/             # TCP/IP layer 4 — Application
├── NTLFlowLyzer/            # TCP/IP layers 2–3 — Internet + Transport
├── QUICFlowLyzer/           # QUIC transport features (-Q)
├── UDPFlowLyzer/            # UDP transport features (-U)
└── DLFlowLyzer/             # TCP/IP layer 1 — Link (PyShark + Wireshark/TShark)
```

Upstream standalone repositories remain available for layer-specific development and citation.

---

## Integrated analyzers

### [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer) — TCP/IP layer 4 (Application)

ALFlowLyzer extracts application-layer flow features from bidirectional flows: HTTP, HTTPS, DNS, MQTT, FTP, SMTP, SSH, Telnet, and related protocols. Install with `pip install -r requirements-al.txt`. It supports application-layer intrusion detection, encrypted traffic analysis, malware communication profiling, and ML-driven behavioral analytics.

**DNS and WHOIS (NetFlowLyzer CLI):**

| Flag | Effect |
|------|--------|
| *(none)* | General AL features on all flows; ~37 DNS/domain columns on DNS flows only; WHOIS off |
| `--al-no-dns` | Skip all DNS/domain columns (~52 features including WHOIS); fastest, quietest AL |
| `--al-whois` | Same as default plus 14 live WHOIS lookup columns on DNS flows |
| `--al-no-whois` | Explicit default (WHOIS off) |

WHOIS features (`dns_domain_registrar`, `dns_domain_age`, `dns_domain_country`, etc.) perform live registry lookups. They are **disabled by default** because they are slow, require network access, and often fail on bulk PCAP runs. Enable them only when you need those columns:

```powershell
python netflowlyzer.py -AL --al-whois -i "..\input" -o "..\output"
```

For large or noisy captures where you only need packet timing and size statistics, use `--al-no-dns`:

```powershell
python netflowlyzer.py -AL --al-no-dns -i "..\input" -o "..\output"
```

### [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer) — TCP/IP layers 2–3 (Internet + TCP transport)

NTLFlowLyzer extracts flow features from the internet and **TCP-focused** transport layers: IP, TCP, ICMP, and related protocols, with statistical, temporal, directional, and behavioral features per bidirectional flow. In NetFlowLyzer, use **`-NTL`** for `{basename}-NTL.csv`. Install with `pip install -r requirements-ntl.txt`. It is aimed at intrusion detection, DDoS analysis, anomaly detection, traffic classification, and large-scale security analytics.

### Transport protocols: UDP and QUIC

At the transport layer, NetFlowLyzer treats **TCP**, **UDP**, and **QUIC** as separate analyzers so each protocol gets dedicated flow logic and feature sets.

| Protocol | Analyzer | In NetFlowLyzer | Output (typical) |
|----------|----------|-----------------|------------------|
| **TCP** | NTLFlowLyzer | `-NTL` | `basename-NTL.csv` |
| **UDP** | UDPFlowLyzer | `-U` | `basename-U.csv` |
| **QUIC** | [QUICFlowLyzer](https://github.com/ahlashkari/QUICFlowLyzer) | `-Q` | `basename-Q.csv` |

#### [UDPFlowLyzer](https://github.com/ahlashkari/UDPFlowLyzer) — UDP transport

UDPFlowLyzer extracts **UDP-specific** L2–L4 flow features (timing, volume, header metrics, entropy, bursts, and related statistics) from bidirectional UDP flows.

**Install:**

```bash
pip install -r requirements-u.txt
```

**Run via NetFlowLyzer:**

```powershell
python netflowlyzer.py -U -i "..\input\2.pcap" -o "..\output"
```

Optional base config: `--udp-config path/to/config.json` (paths are overridden per run). Default `label` column is empty for manual tagging.

**No UDP in the capture?** `-U` may finish with `{basename}-U.csv` containing **headers only** and **zero data rows**. NetFlowLyzer prints: `Warning: no UDP flows found; ... contains headers only.`

**Run standalone (upstream CLI):**

```bash
python -m UDPFlowLyzer --config UDPFlowLyzer/config.json
```

#### [QUICFlowLyzer](https://github.com/ahlashkari/QUICFlowLyzer) — QUIC transport

QUICFlowLyzer extracts **header-level** QUIC packet and flow features from PCAP/PCAPNG traffic **without decrypting payloads**. It supports single PCAP files, batch globs, and optional VXLAN decapsulation.

**Install:**

```bash
pip install -r requirements-q.txt
```

**Run via NetFlowLyzer (recommended):**

```powershell
python netflowlyzer.py -Q -i "..\input\2.pcap" -o "..\output"
```

**No QUIC in the capture?** `-Q` finishes quickly. Output is `{basename}-Q.csv` with column headers and an empty **`label`** column, but **zero data rows**. NetFlowLyzer prints: `Warning: no QUIC flows found; ... contains headers only.`

**Cloud / VXLAN captures:**

```powershell
python netflowlyzer.py -Q --q-vxlan-ip 10.0.0.1 --q-allow-mirrored-sport -i capture.pcap -o "..\output"
```

| Flag | Purpose |
|------|---------|
| `--q-vxlan-ip` | Outer VXLAN endpoint IP |
| `--q-vxlan-port` | VXLAN UDP port (default 4789) |
| `--q-allow-mirrored-sport` | AWS traffic mirroring quirk |
| `--q-inner-cidr` | Filter inner IPs after decap (repeatable) |
| `--q-idle-gap-sec` | Active/idle episode threshold (default 1.0 s) |
| `--q-verbose` | Per-packet QUIC parse logs (default: off) |

**Run standalone (upstream CLI):**

```bash
cd QUICFlowLyzer
pip install -r requirements.txt
python -m quic_cap.features.feat_cli --pcap input.pcap --features-out output_features.csv --verbose
```

### [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer) — TCP/IP layer 1 (Link)

DLFlowLyzer performs link-layer analysis for enterprise switching environments: Ethernet, ARP, STP, CDP, DHCP, DTP, ISL, LLC, VLAN-related traffic, and other control-plane protocols. It supports link-layer behavioral profiling, attack detection, and switching-protocol analysis.

- **Install Python deps:** `pip install -r requirements-dl.txt` (includes **PyShark**)
- **Install Wireshark** with **TShark** enabled (system binary, not a pip package)
- **Run:** `python netflowlyzer.py -DL -i capture.pcap -o out` — on Windows, NetFlowLyzer locates default TShark automatically (see [TShark and PyShark](#tshark-and-pyshark-dl))

DL is slower on large PCAPs than AL/NTL because PyShark drives TShark packet-by-packet.

---

## Tips

- **AL modes:** Default is DNS on, WHOIS off. Use `--al-no-dns` for bulk runs when you do not need domain/TTL columns. Use `--al-whois` only when registrar/age/country columns are required.
- **AL DNS errors:** DNS flows with empty domain names no longer flood the terminal; errors are summarized once per flow. Remaining errors usually mean malformed DNS payloads — use `--al-no-dns` if you do not need those columns.
- **Large PCAPs:** DL can take a long time (tens of minutes per file). Test with `-NTL`, `-AL`, or `-Q` first, or a single file via `-i capture.pcap`. For AL-only smoke tests, add `--al-no-dns`.
- **QUIC vs NTL:** Use **`-Q`** for QUIC-specific features; **`-NTL`** remains TCP/IP internet + TCP transport. Use **UDPFlowLyzer** upstream for dedicated UDP feature CSVs.
- **QUIC empty output:** On PCAPs without QUIC (e.g. TCP-only HTTPS), `-Q` writes headers only — that is normal. Add `-Q` only when the capture contains QUIC/HTTP3 (UDP, often port 443).
- **QUIC VXLAN:** For mirrored cloud traffic, pass `--q-vxlan-ip` and optionally `--q-allow-mirrored-sport` on `netflowlyzer.py`.
- **`-DL` / TShark:** PyShark (pip) plus Wireshark/TShark (system). On Windows, `netflowlyzer.py -DL` adds `C:\Program Files\Wireshark` to `PATH` automatically; `tshark -v` failing in PowerShell does not always mean `-DL` will fail. Install Wireshark if `-DL` errors about missing `tshark`.
- **Windows Firewall:** Allow Python once when prompted; use default single-process mode (do not pass `--parallel`) to minimize repeated prompts. You may also need to allow `tshark.exe` once for DL. **`-U`** uses the same default (threads in one process, not multiple Python workers).
- **Configs:** Layer-specific defaults live in `ALFlowLyzer/config.json`, `NTLFlowLyzer/config.json`, and `UDPFlowLyzer/config.json`. NetFlowLyzer writes temporary runtime configs per layer run and **removes them when that layer finishes**. DL intermediate work files are also cleaned up automatically.

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

**UDPFlowLyzer & QuicFlowLyzer**
* [**Sepehr Jafari:**](https://github.com/Aeripsen) Research Assistant - York University (2025 - 2026)

**DLFlowLyzer**


* [**Amirhossein Ahmadnejad Roudsari**](https://github.com/aahmadnejad) — Graduate researcher and developer, York University (2024–2025)

---

## Acknowledgement

This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada (NSERC, #RGPIN-2020-04701) and the Canada Research Chair (Tier II, #CRC-2021-00340) held by Arash Habibi Lashkari.

---

## License

NetFlowLyzer is released under the **GNU General Public License v3.0 (GPL-3.0)**. See [LICENSE](LICENSE) in the repository root.

This project integrates code from [ALFlowLyzer](https://github.com/ahlashkari/ALFlowLyzer), [NTLFlowLyzer](https://github.com/ahlashkari/NTLFlowLyzer), [DLFlowLyzer](https://github.com/ahlashkari/DLFlowLyzer), [QUICFlowLyzer](https://github.com/ahlashkari/QUICFlowLyzer), and [UDPFlowLyzer](https://github.com/ahlashkari/UDPFlowLyzer). Each upstream repository may define its own license terms; `DLFlowLyzer/LICENSE` is also included under the bundled `DLFlowLyzer/` folder.
