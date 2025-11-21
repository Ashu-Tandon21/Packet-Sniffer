# Python-Scapy-Packet-Sniffer
A quick packet Sniffer developed using python v3 with scapy to capture TCP, UDP and ICMP Packets in linux .This script is tested on linux Operating System on python version3. The script captures all the incoming and outgoing packets from all interface of the machine. Once the packets are captures they are classfies into TCP, UDP and ICMP packets based on their header.Under each classification the packets are categorized into incoming and outgoing packets.Some of the information captures by Packet Sniffer is Time Stamp, Source Mac,Destination Mac,source IP Address, Destination IP Address, 
. The dependent modules are Builtin [os](https://docs.python.org/3/library/os.html), [datetime](https://docs.python.org/3/library/datetime.html),[socket](https://docs.python.org/3/library/socket.html), [time](https://docs.python.org/3/library/time.html), and external [Scapy](https://scapy.net/) . Scapy is not pre-installed in Linux hence, needs to be installed.

# Installing External Modules:   
```
sudo apt install scapy  
```

# To download and Run Script
```
git clone https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer.git  
```
```
cd Python-Scapy-Packet-Sniffer/  
```
```
sudo python3 python-packet-sniffer.py       
## CSV output

When the sniffer is stopped (Ctrl+C) it will save collected packet metadata to a timestamped CSV file. By default the script writes CSV files to an `output/` subfolder in the directory where you run the script.

Columns written:
- timestamp (ISO)
- protocol (TCP/UDP/ICMP/TEST)
- direction (IN/OUT)
- length (bytes)
- ip_version
- src_mac, dst_mac
```markdown
# Python-Scapy-Packet-Sniffer
A quick packet sniffer written in Python 3 using Scapy. The script captures TCP, UDP and ICMP packets (incoming and outgoing) on Linux and prints a human-readable line for each packet. When the capture stops the script saves captured packet metadata into CSV files for later analysis.

The script depends on the Python standard library (`os`, `datetime`, `socket`, `time`, etc.) and on Scapy for packet capture: https://scapy.net/.

## Installing Scapy

On Debian/Ubuntu you can install Scapy via apt (system package) or pip (recommended inside a virtualenv):

```bash
sudo apt install scapy                # system package
# or (recommended)
python3 -m pip install --user scapy
```

## Get the code

```bash
git clone https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer.git
cd Python-Scapy-Packet-Sniffer/
```

## Running the sniffer

Capture interactively (typical, root required to capture raw packets):

```bash
sudo python3 python-packet-sniffer.py
```

Quick test mode (no raw capture; writes a sample CSV row):

```bash
python3 python-packet-sniffer.py --test
```

Timed capture (auto-stop after N seconds):

```bash
sudo python3 python-packet-sniffer.py --duration 10
```

Specify a custom output directory (useful to avoid root-owned files when running under sudo):

```bash
python3 python-packet-sniffer.py --outdir /path/you/own
```

## CSV output

When the sniffer stops (Ctrl+C or when `--duration` ends) the script saves two CSVs to the output directory:

- packets_YYYYmmdd_HHMMSS.csv — a row per captured packet
- summary_YYYYmmdd_HHMMSS.csv — aggregated frequency counts (protocols, directions, IP versions, top ports)

By default the files are written to `./output/` (a subfolder in the directory where you ran the script). Use `--outdir` to override.

The packet CSV columns are:

- timestamp (ISO 8601)
- protocol (TCP / UDP / ICMP / TEST)
- direction (IN / OUT)
- length (bytes)
- ip_version
- src_mac, dst_mac
- src_port, dst_port
- src_ip, dst_ip
- message — the exact human-readable text that was printed to the terminal for that packet (so each CSV row contains the same output you see on screen)

Example: when the CSV is written the script prints a line like:

```
Writing CSV to: /full/path/output/packets_20251121_163702.csv
Saved 157 packets to CSV: /full/path/output/packets_20251121_163702.csv
Saved summary to CSV: /full/path/output/summary_20251121_163702.csv
```

The summary CSV contains rows in the form: metric,label,count and includes protocol counts, direction counts, IP version counts, and the top source/destination ports observed.

## Notes & permissions

- If you run the script with `sudo`, output files will be created with root ownership. To avoid this either run the script without sudo (see capabilities options) or use `--outdir` pointing to a directory you own.
- If you want, you can set capabilities on the Python interpreter to capture packets without sudo (advanced):

```bash
sudo setcap cap_net_raw+ep $(which python3)
```

(Only do the above if you understand the implications.)

## Troubleshooting

- If your CSV appears empty, confirm packets were actually printed to the terminal during the capture (you should see lines like "[2025-11-21 16:36:57.946041] UDP-OUT: ...").
- If files are root-owned and you can't open them as your user, re-run the script with `--outdir /home/your-user/somewhere` or change ownership after capture.

![Packet Screenshot](https://github.com/Roshan-Poudel/Python-Scapy-Packet-Sniffer/blob/master/packet%20screenshot.jpg)
```