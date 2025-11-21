#!/usr/bin/python

from scapy.all import sniff, TCP, UDP, ICMP, IP, IPv6
import socket
import datetime
import csv
import os
import argparse
from collections import Counter

# Directory where the script was started (the working directory where you ran the script)
START_CWD = os.getcwd()
DEFAULT_OUTDIR = os.path.join(START_CWD, 'output')

def get_local_ip():
    # Get the local network IP address of the host
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

# Local IP address of the machine
local_ip = get_local_ip()

def network_monitoring(pkt):
    # Capture the current timestamp
    timestamp = datetime.datetime.now()

    # Check for TCP packets with IP or IPv6 layers
    if pkt.haslayer(TCP):
        if pkt.haslayer(IP):
            ip_layer = IP
        elif pkt.haslayer(IPv6):
            ip_layer = IPv6
        else:
            return

        # Determine if it's an incoming or outgoing TCP packet
        direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
        length = len(pkt)
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        src_ip = pkt[ip_layer].src
        dst_ip = pkt[ip_layer].dst
        message = (
            f"[{timestamp}] TCP-{direction}: {length} Bytes "
            f"SRC-MAC: {pkt.src} DST-MAC: {pkt.dst} "
            f"SRC-PORT: {src_port} DST-PORT: {dst_port} "
            f"SRC-IP: {src_ip} DST-IP: {dst_ip}"
        )
        print(message)

        # Save metadata for CSV export
        captured_packets.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'TCP',
            'direction': direction,
            'length': length,
            'ip_version': pkt[ip_layer].version if hasattr(pkt[ip_layer], 'version') else '',
            'src_mac': pkt.src,
            'dst_mac': pkt.dst,
            'src_port': src_port,
            'dst_port': dst_port,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'message': message,
        })
        # update counters
        protocol_counter.update(['TCP'])
        direction_counter.update([direction])
        if hasattr(pkt[ip_layer], 'version'):
            ip_version_counter.update([str(pkt[ip_layer].version)])
        if src_port:
            src_port_counter.update([str(src_port)])
        if dst_port:
            dst_port_counter.update([str(dst_port)])
        # Debug: show append count so user can confirm packets are being collected
        print(f"Appended packet — total captured: {len(captured_packets)}")

    # Check for UDP packets with IP layer
    elif pkt.haslayer(UDP) and pkt.haslayer(IP):
        # Determine if it's an incoming or outgoing UDP packet
        direction = "IN" if pkt[IP].dst == local_ip else "OUT"
        length = len(pkt)
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        message = (
            f"[{timestamp}] UDP-{direction}: {length} Bytes "
            f"SRC-MAC: {pkt.src} DST-MAC: {pkt.dst} "
            f"SRC-PORT: {src_port} DST-PORT: {dst_port} "
            f"SRC-IP: {src_ip} DST-IP: {dst_ip}"
        )
        print(message)

        captured_packets.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'UDP',
            'direction': direction,
            'length': length,
            'ip_version': pkt[IP].version if hasattr(pkt[IP], 'version') else '',
            'src_mac': pkt.src,
            'dst_mac': pkt.dst,
            'src_port': src_port,
            'dst_port': dst_port,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'message': message,
        })
        # update counters
        protocol_counter.update(['UDP'])
        direction_counter.update([direction])
        if hasattr(pkt[IP], 'version'):
            ip_version_counter.update([str(pkt[IP].version)])
        if src_port:
            src_port_counter.update([str(src_port)])
        if dst_port:
            dst_port_counter.update([str(dst_port)])
        print(f"Appended packet — total captured: {len(captured_packets)}")

    # Check for ICMP packets with IP layer
    elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
        # Determine if it's an incoming or outgoing ICMP packet
        direction = "IN" if pkt[IP].dst == local_ip else "OUT"
        length = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        message = (
            f"[{timestamp}] ICMP-{direction}: {length} Bytes "
            f"IP-Version: {pkt[IP].version} "
            f"SRC-MAC: {pkt.src} DST-MAC: {pkt.dst} "
            f"SRC-IP: {src_ip} DST-IP: {dst_ip}"
        )
        print(message)

        captured_packets.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'ICMP',
            'direction': direction,
            'length': length,
            'ip_version': pkt[IP].version if hasattr(pkt[IP], 'version') else '',
            'src_mac': pkt.src,
            'dst_mac': pkt.dst,
            'src_port': '',
            'dst_port': '',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'message': message,
        })
        # update counters
        protocol_counter.update(['ICMP'])
        direction_counter.update([direction])
        if hasattr(pkt[IP], 'version'):
            ip_version_counter.update([str(pkt[IP].version)])
        print(f"Appended packet — total captured: {len(captured_packets)}")

# Container for captured packet metadata; appended by network_monitoring
captured_packets = []
# Counters for summary statistics
protocol_counter = Counter()
direction_counter = Counter()
ip_version_counter = Counter()
src_port_counter = Counter()
dst_port_counter = Counter()

def save_csv(packets, out_dir='.'):
    """Save captured packet metadata to a timestamped CSV file in out_dir."""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    fname = datetime.datetime.now().strftime('packets_%Y%m%d_%H%M%S.csv')
    path = os.path.join(out_dir, fname)
    # Print exact path before writing so user can see where file will be created
    print(f"Writing CSV to: {path}")
    fieldnames = ['timestamp', 'protocol', 'direction', 'length', 'ip_version',
                  'src_mac', 'dst_mac', 'src_port', 'dst_port', 'src_ip', 'dst_ip', 'message']

    with open(path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for p in packets:
            # Ensure keys exist (avoid KeyError)
            row = {k: p.get(k, '') for k in fieldnames}
            writer.writerow(row)

    print(f"Saved {len(packets)} packets to CSV: {path}")

    # Also write a summary CSV with frequency counts
    try:
        save_summary(out_dir)
    except Exception:
        # don't fail the main save if summary write fails
        pass

        # Automatically run visualizer after saving CSVs
        import subprocess
        visualizer_path = os.path.join(START_CWD, 'visualize_ports.py')
        if os.path.isfile(visualizer_path):
            try:
                print(f"Running visualizer: {visualizer_path}")
                subprocess.run(['python3', visualizer_path, '--outdir', out_dir], check=False)
            except Exception as e:
                print(f"Visualizer failed: {e}")
        else:
            print(f"Visualizer script not found at {visualizer_path}")


def save_summary(out_dir='.'):
    """Write summary frequency CSVs (protocols, directions, ip versions, top ports)."""
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    fname = datetime.datetime.now().strftime('summary_%Y%m%d_%H%M%S.csv')
    path = os.path.join(out_dir, fname)

    # Prepare rows: metric,label,count
    rows = []
    for label, cnt in protocol_counter.most_common():
        rows.append(('protocol', label, cnt))
    for label, cnt in direction_counter.most_common():
        rows.append(('direction', label, cnt))
    for label, cnt in ip_version_counter.most_common():
        rows.append(('ip_version', label, cnt))

    # top N ports
    TOP_N = 10
    for label, cnt in src_port_counter.most_common(TOP_N):
        rows.append(('src_port', label, cnt))
    for label, cnt in dst_port_counter.most_common(TOP_N):
        rows.append(('dst_port', label, cnt))

    with open(path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['metric', 'label', 'count'])
        for r in rows:
            writer.writerow(r)

    # Print a compact summary to console
    print('\nSummary:')
    print('Protocols:', dict(protocol_counter))
    print('Directions:', dict(direction_counter))
    print('IP versions:', dict(ip_version_counter))
    print('Top src ports:', src_port_counter.most_common(10))
    print('Top dst ports:', dst_port_counter.most_common(10))
    print(f"Saved summary to: {path}\n")


def _run_test_write(out_dir=START_CWD):
    """Write a small test CSV to verify save_csv works and exit."""
    sample = [{
        'timestamp': datetime.datetime.now().isoformat(),
        'protocol': 'TEST',
        'direction': 'OUT',
        'length': 0,
        'ip_version': '',
        'src_mac': '',
        'dst_mac': '',
        'src_port': '',
        'dst_port': '',
        'src_ip': '',
        'dst_ip': '',
        'message': f"[{datetime.datetime.now()}] TEST: sample row",
    }]
    save_csv(sample, out_dir=out_dir)
    print('Test CSV write complete.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple Scapy packet sniffer that can save metadata to CSV')
    parser.add_argument('--test', action='store_true', help='Write a small test CSV to the working directory (or --outdir) and exit')
    parser.add_argument('--outdir', default=DEFAULT_OUTDIR, help='Directory to save CSV files (default: ./output under the run directory)')
    parser.add_argument('--duration', type=int, default=None, help='Run capture for N seconds then auto-save (no Ctrl+C needed)')
    args = parser.parse_args()

    if args.test:
        _run_test_write(out_dir=args.outdir)
        raise SystemExit(0)

    print(f"Starting network monitoring on local IP: {local_ip}")
    print(f"CSV files will be saved to: {args.outdir}")
    # Ensure default output directory is obvious
    if args.outdir == DEFAULT_OUTDIR:
        print(f"Using default output folder: {os.path.relpath(DEFAULT_OUTDIR, START_CWD)}")
    try:
        # store=False avoids keeping packets in Scapy's global store
        if args.duration and args.duration > 0:
            print(f"Running capture for {args.duration} seconds...")
            sniff(prn=network_monitoring, store=False, timeout=args.duration)
            print("Capture finished (duration). Saving CSV...")
            save_csv(captured_packets, out_dir=args.outdir)
        else:
            sniff(prn=network_monitoring, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user. Saving CSV...")
        # Save into the directory where the script was started
        save_csv(captured_packets, out_dir=args.outdir)
    except Exception as e:
        print(f"Error while sniffing: {e}")
